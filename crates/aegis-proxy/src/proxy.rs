use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use aegis_core::audit::AuditEntry;
use aegis_core::decision::Decision;

use crate::handler::ProxyHandler;
use crate::tls::CertAuthority;

/// The HTTP forward proxy server with optional HTTPS MITM interception.
pub struct AegisProxy {
    handler: Arc<ProxyHandler>,
    listen_addr: SocketAddr,
    ca: Option<Arc<CertAuthority>>,
}

impl AegisProxy {
    pub fn new(handler: Arc<ProxyHandler>, listen_addr: SocketAddr) -> Self {
        Self {
            handler,
            listen_addr,
            ca: None,
        }
    }

    /// Enable HTTPS MITM interception with the given CA.
    pub fn with_ca(mut self, ca: CertAuthority) -> Self {
        self.ca = Some(Arc::new(ca));
        self
    }

    /// Start the proxy server.
    pub async fn run(self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;

        if self.ca.is_some() {
            tracing::info!(
                "Aegis proxy listening on {} (MITM enabled)",
                self.listen_addr
            );
        } else {
            tracing::info!(
                "Aegis proxy listening on {} (passthrough mode)",
                self.listen_addr
            );
        }

        let ca = self.ca.clone();

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let handler = self.handler.clone();
            let ca = ca.clone();

            tokio::spawn(async move {
                let io = TokioIo::new(stream);

                let service = service_fn(move |req: Request<Incoming>| {
                    let handler = handler.clone();
                    let ca = ca.clone();
                    async move {
                        Ok::<_, Infallible>(
                            handle_request(req, handler, ca, peer_addr).await,
                        )
                    }
                });

                if let Err(e) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await
                {
                    tracing::debug!("Connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    handler: Arc<ProxyHandler>,
    ca: Option<Arc<CertAuthority>>,
    peer_addr: SocketAddr,
) -> Response<Full<Bytes>> {
    if req.method() == Method::CONNECT {
        return handle_connect(req, handler, ca, peer_addr).await;
    }

    handle_plain_http(req, handler).await
}

/// Handle plain HTTP proxy requests (non-CONNECT).
async fn handle_plain_http(
    req: Request<Incoming>,
    handler: Arc<ProxyHandler>,
) -> Response<Full<Bytes>> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();

    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.to_string().to_lowercase(), v.to_string());
        }
    }

    let body = match req.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            if bytes.is_empty() {
                None
            } else {
                Some(bytes)
            }
        }
        Err(_) => None,
    };

    let (verdict, mut audit_entry) = handler.evaluate(&method, &uri, headers.clone(), body.clone()).await;

    match verdict.decision {
        Decision::Deny => {
            tracing::warn!(
                "[BLOCKED] {} {} -> {} ({})",
                method, uri, verdict.reason, verdict.source,
            );
            let response = blocked_response(&verdict.reason);
            if let Some(ref mut entry) = audit_entry {
                let meta = capture_response_meta(response.status(), response.headers(), &Bytes::new());
                set_response_on_entry(entry, &meta);
                handler.log_entry(entry);
            }
            response
        }
        Decision::Allow => {
            tracing::info!("[ALLOWED] {} {}", method, uri);
            if let Ok(parsed) = url::Url::parse(&uri) {
                let host = parsed.host_str().unwrap_or("");
                handler.inject_secrets(host, parsed.path(), &mut headers);
            }
            let (response, meta) = forward_request(&method, &uri, headers, body).await;
            if let Some(ref mut entry) = audit_entry {
                set_response_on_entry(entry, &meta);
                handler.log_entry(entry);
            }
            response
        }
    }
}

/// Handle CONNECT requests.
/// If CA is available: MITM intercept (terminate TLS, inspect, re-encrypt).
/// If no CA: plain TCP tunnel (passthrough, no inspection).
async fn handle_connect(
    req: Request<Incoming>,
    handler: Arc<ProxyHandler>,
    ca: Option<Arc<CertAuthority>>,
    _peer_addr: SocketAddr,
) -> Response<Full<Bytes>> {
    let host_port = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();

    let (host, port) = parse_host_port(&host_port);

    // Bypass policy for Aegis's own services
    if handler.is_bypass(&host, port) {
        // Fall through to tunnel setup
    } else {
        // Scope check (with audit logging)
        let verdict = handler.config.engine().evaluate_connect(&host, port);
        if verdict.is_deny() {
            tracing::warn!("[BLOCKED] CONNECT {} -> {} ({})", host_port, verdict.reason, verdict.source);
            return blocked_response(&verdict.reason);
        }
    }

    let host_clone = host.clone();
    let host_port_clone = host_port.clone();

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Some(ca) = ca {
                    // MITM mode: terminate TLS, inspect, forward
                    if let Err(e) = handle_mitm(
                        upgraded,
                        &host_clone,
                        &host_port_clone,
                        handler,
                        ca,
                    )
                    .await
                    {
                        tracing::debug!("MITM error for {}: {}", host_port_clone, e);
                    }
                } else {
                    // Passthrough mode: just tunnel TCP
                    let mut upgraded = TokioIo::new(upgraded);
                    match tokio::net::TcpStream::connect(&host_port_clone).await {
                        Ok(mut target) => {
                            let _ =
                                tokio::io::copy_bidirectional(&mut upgraded, &mut target).await;
                        }
                        Err(e) => {
                            tracing::error!(
                                "Failed to connect to {}: {}",
                                host_port_clone,
                                e
                            );
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Upgrade error: {}", e);
            }
        }
    });

    // Return 200 to signal tunnel established
    Response::new(Full::new(Bytes::new()))
}

/// MITM handler: accepts TLS from client, parses HTTP requests inside the tunnel,
/// evaluates them through the policy engine, and forwards to the real target.
async fn handle_mitm(
    upgraded: hyper::upgrade::Upgraded,
    hostname: &str,
    host_port: &str,
    handler: Arc<ProxyHandler>,
    ca: Arc<CertAuthority>,
) -> anyhow::Result<()> {
    // Get TLS acceptor for this hostname
    let tls_acceptor = ca.get_tls_acceptor(hostname)?;

    // Terminate TLS with the client
    let tls_stream = tls_acceptor.accept(TokioIo::new(upgraded)).await?;
    let io = TokioIo::new(tls_stream);

    tracing::debug!("[MITM] TLS established for {}", hostname);

    let host_for_service = hostname.to_string();
    let host_port_for_service = host_port.to_string();

    // Serve HTTP/1.1 inside the TLS tunnel
    let service = service_fn(move |req: Request<Incoming>| {
        let handler = handler.clone();
        let host = host_for_service.clone();
        let host_port = host_port_for_service.clone();

        async move {
            let method = req.method().to_string();
            let path = req.uri().path_and_query().map(|pq| pq.to_string()).unwrap_or("/".into());
            let full_uri = format!("https://{host}{path}");

            let mut headers = HashMap::new();
            for (name, value) in req.headers() {
                if let Ok(v) = value.to_str() {
                    headers.insert(name.to_string().to_lowercase(), v.to_string());
                }
            }

            let body = match req.collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    if bytes.is_empty() { None } else { Some(bytes) }
                }
                Err(_) => None,
            };

            let (verdict, mut audit_entry) = handler.evaluate(&method, &full_uri, headers.clone(), body.clone()).await;

            let response = match verdict.decision {
                Decision::Deny => {
                    tracing::warn!(
                        "[BLOCKED] {} {} -> {} ({})",
                        method, full_uri, verdict.reason, verdict.source,
                    );
                    let resp = blocked_response(&verdict.reason);
                    if let Some(ref mut entry) = audit_entry {
                        let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
                        set_response_on_entry(entry, &meta);
                        handler.log_entry(entry);
                    }
                    resp
                }
                Decision::Allow => {
                    tracing::info!("[ALLOWED] {} {}", method, full_uri);
                    let url_path = path.split('?').next().unwrap_or(&path);
                    handler.inject_secrets(&host, url_path, &mut headers);
                    let (resp, meta) = forward_https_request(&method, &host, &host_port, &path, headers, body).await;
                    if let Some(ref mut entry) = audit_entry {
                        set_response_on_entry(entry, &meta);
                        handler.log_entry(entry);
                    }
                    resp
                }
            };

            Ok::<_, Infallible>(response)
        }
    });

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .serve_connection(io, service)
        .await
        .map_err(|e| anyhow::anyhow!("MITM connection error: {}", e))?;

    Ok(())
}

/// Forward an HTTPS request to the real target (connects with TLS). Returns response and metadata.
async fn forward_https_request(
    method: &str,
    host: &str,
    host_port: &str,
    path: &str,
    headers: HashMap<String, String>,
    body: Option<Bytes>,
) -> (Response<Full<Bytes>>, ResponseMeta) {
    // Connect to the real target
    let tcp = match tokio::net::TcpStream::connect(host_port).await {
        Ok(s) => s,
        Err(e) => {
            let resp = error_response(502, &format!("Failed to connect to {host_port}: {e}"));
            let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
            return (resp, meta);
        }
    };

    // Establish TLS to the target
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth(),
    ));

    let server_name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
        Ok(sn) => sn,
        Err(e) => {
            let resp = error_response(502, &format!("Invalid server name {host}: {e}"));
            let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
            return (resp, meta);
        }
    };

    let tls_stream = match connector.connect(server_name, tcp).await {
        Ok(s) => s,
        Err(e) => {
            let resp = error_response(502, &format!("TLS connection to {host} failed: {e}"));
            let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
            return (resp, meta);
        }
    };

    let io = TokioIo::new(tls_stream);

    // Send HTTP request through the TLS connection
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(h) => h,
        Err(e) => {
            let resp = error_response(502, &format!("HTTP handshake with {host} failed: {e}"));
            let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
            return (resp, meta);
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("Connection to target closed: {}", e);
        }
    });

    let mut builder = Request::builder()
        .method(method)
        .uri(path);

    for (name, value) in &headers {
        if matches!(
            name.as_str(),
            "proxy-connection" | "proxy-authorization" | "te" | "trailer"
        ) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }

    // Ensure Host header is set
    if !headers.contains_key("host") {
        builder = builder.header("host", host);
    }

    let outgoing_body = body.unwrap_or_default();
    let req = match builder.body(Full::new(outgoing_body)) {
        Ok(r) => r,
        Err(e) => {
            let resp = error_response(502, &format!("Failed to build request: {e}"));
            let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
            return (resp, meta);
        }
    };

    match sender.send_request(req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();

            match resp.into_body().collect().await {
                Ok(collected) => {
                    let body_bytes = collected.to_bytes();
                    let meta = capture_response_meta(status, &resp_headers, &body_bytes);

                    let mut response = Response::builder().status(status);
                    for (name, value) in &resp_headers {
                        response = response.header(name, value);
                    }
                    let response = response
                        .body(Full::new(body_bytes))
                        .unwrap_or_else(|_| error_response(502, "Failed to build response"));

                    (response, meta)
                }
                Err(e) => {
                    let resp = error_response(502, &format!("Failed to read response: {e}"));
                    let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
                    (resp, meta)
                }
            }
        }
        Err(e) => {
            let resp = error_response(502, &format!("Failed to send request to {host}: {e}"));
            let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
            (resp, meta)
        }
    }
}

/// Forward a plain HTTP request to the target. Returns response and metadata for audit.
async fn forward_request(
    method: &str,
    uri: &str,
    headers: HashMap<String, String>,
    body: Option<Bytes>,
) -> (Response<Full<Bytes>>, ResponseMeta) {
    let client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        Full<Bytes>,
    > = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();

    let mut builder = Request::builder().method(method).uri(uri);

    for (name, value) in &headers {
        if matches!(
            name.as_str(),
            "proxy-connection" | "proxy-authorization" | "te" | "trailer"
        ) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }

    let outgoing_body = body.unwrap_or_default();
    let req = match builder.body(Full::new(outgoing_body)) {
        Ok(r) => r,
        Err(e) => {
            let resp = error_response(502, &format!("Failed to build request: {e}"));
            let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
            return (resp, meta);
        }
    };

    match client.request(req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();

            match resp.into_body().collect().await {
                Ok(collected) => {
                    let body_bytes = collected.to_bytes();
                    let meta = capture_response_meta(status, &resp_headers, &body_bytes);

                    let mut response = Response::builder().status(status);
                    for (name, value) in &resp_headers {
                        response = response.header(name, value);
                    }
                    let response = response
                        .body(Full::new(body_bytes))
                        .unwrap_or_else(|_| error_response(502, "Failed to build response"));

                    (response, meta)
                }
                Err(e) => {
                    let resp = error_response(502, &format!("Failed to read response body: {e}"));
                    let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
                    (resp, meta)
                }
            }
        }
        Err(e) => {
            let resp = error_response(502, &format!("Failed to forward request: {e}"));
            let meta = capture_response_meta(resp.status(), resp.headers(), &Bytes::new());
            (resp, meta)
        }
    }
}

fn parse_host_port(authority: &str) -> (String, u16) {
    if let Some((host, port_str)) = authority.rsplit_once(':') {
        let port = port_str.parse().unwrap_or(443);
        (host.to_string(), port)
    } else {
        (authority.to_string(), 443)
    }
}

/// Response metadata captured for audit logging.
struct ResponseMeta {
    status: u16,
    headers: HashMap<String, String>,
    body: Option<Bytes>,
    content_type: Option<String>,
}

/// Extract response metadata from status, headers, and body bytes.
fn capture_response_meta(
    status: hyper::StatusCode,
    headers: &hyper::HeaderMap,
    body: &Bytes,
) -> ResponseMeta {
    let mut resp_headers = HashMap::new();
    for (name, value) in headers {
        if let Ok(v) = value.to_str() {
            resp_headers.insert(name.to_string().to_lowercase(), v.to_string());
        }
    }
    let content_type = resp_headers.get("content-type").cloned();
    let body = if body.is_empty() { None } else { Some(body.clone()) };
    ResponseMeta {
        status: status.as_u16(),
        headers: resp_headers,
        body,
        content_type,
    }
}

/// Attach response metadata to an audit entry.
fn set_response_on_entry(entry: &mut AuditEntry, meta: &ResponseMeta) {
    entry.set_response(
        meta.status,
        meta.headers.clone(),
        meta.body.as_deref(),
        meta.content_type.as_deref(),
    );
}

fn blocked_response(reason: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "error": format!("[AEGIS] {reason}"),
        "blocked": true,
        "reason": reason,
        "source": "aegis"
    });

    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .header("x-blocked-by", "aegis")
        .header("x-aegis-reason", reason)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("[AEGIS] Blocked"))))
}

fn error_response(status: u16, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY))
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(message.to_string())))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Error"))))
}

/// Certificate verifier that accepts any certificate (for connecting to target).
/// This is intentional for a MITM proxy -- we verify on the client side via our CA.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
