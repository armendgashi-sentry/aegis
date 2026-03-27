use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{self, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use bytes::Bytes;

use aegis_core::analyzer::{RequestContext, ShellContext};
use aegis_core::audit::{self, AuditEntry, Layer};
use aegis_core::decision::Decision;

use crate::state::AppState;

#[derive(serde::Deserialize)]
pub struct EventsQuery {
    pub limit: Option<usize>,
    pub decision: Option<String>,
}

/// GET /api/stats
pub async fn get_stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let snap = state.stats.snapshot();
    Json(serde_json::json!({
        "total": snap.total,
        "allowed": snap.allowed,
        "denied": snap.denied,
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running",
    }))
}

/// GET /api/health
pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

/// WS /api/live - Real-time event stream via WebSocket
pub async fn live_events(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

/// GET /api/logs - List available audit log files (sessions)
pub async fn list_logs(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let dir = match &state.audit_dir {
        Some(d) => d.clone(),
        None => aegis_core::session::LOG_DIR.to_string(),
    };

    let logs = audit::find_audit_logs(Path::new(&dir));
    let current_session = aegis_core::session::session_id();

    let files: Vec<serde_json::Value> = logs
        .iter()
        .map(|p| {
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
            // Extract session timestamp from filename: aegis-YYYY-MM-DD_HH-MM-SS.jsonl
            let session = name
                .strip_prefix("aegis-")
                .and_then(|s| s.strip_suffix(".jsonl"))
                .unwrap_or(&name);
            let is_current = session == current_session;
            serde_json::json!({
                "name": name,
                "path": p.to_string_lossy(),
                "size": size,
                "session": session,
                "current": is_current,
            })
        })
        .collect();

    Json(serde_json::json!({
        "logs": files,
        "current_session": current_session,
    }))
}

#[derive(serde::Deserialize)]
pub struct LogQuery {
    pub file: String,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub decision: Option<String>,
    pub search: Option<String>,
}

/// GET /api/logs/entries?file=<path>&limit=N&offset=N&decision=allow|deny&search=term
pub async fn get_log_entries(Query(query): Query<LogQuery>) -> Json<serde_json::Value> {
    let path = Path::new(&query.file);
    let entries = match audit::read_audit_log(path) {
        Ok(e) => e,
        Err(e) => {
            return Json(serde_json::json!({
                "error": format!("Failed to read log: {e}")
            }));
        }
    };

    let search_lower = query.search.as_deref().unwrap_or("").to_lowercase();
    let has_search = !search_lower.is_empty();

    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|entry| {
            if let Some(ref d) = query.decision {
                match d.as_str() {
                    "allow" => {
                        if entry.decision != Decision::Allow {
                            return false;
                        }
                    }
                    "deny" => {
                        if entry.decision != Decision::Deny {
                            return false;
                        }
                    }
                    _ => {}
                }
            }
            if has_search {
                entry_matches_search(entry, &search_lower)
            } else {
                true
            }
        })
        .collect();

    let total = filtered.len();
    let allowed = filtered.iter().filter(|e| e.decision == Decision::Allow).count();
    let denied = filtered.iter().filter(|e| e.decision == Decision::Deny).count();

    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(1000);
    let start = offset.min(filtered.len());
    let end = (start + limit).min(filtered.len());
    let page = &filtered[start..end];

    Json(serde_json::json!({
        "entries": page,
        "stats": {
            "total": total,
            "allowed": allowed,
            "denied": denied,
        },
        "pagination": {
            "offset": start,
            "limit": limit,
            "has_more": end < total,
        }
    }))
}

/// Check if an audit entry matches a search query (case-insensitive).
fn entry_matches_search(entry: &AuditEntry, query: &str) -> bool {
    entry.url.to_lowercase().contains(query)
        || entry.method.to_lowercase().contains(query)
        || entry.reason.to_lowercase().contains(query)
        || entry.source.to_lowercase().contains(query)
        || entry.host.to_lowercase().contains(query)
        || entry.body.as_deref().unwrap_or("").to_lowercase().contains(query)
}

// --- Evaluate API endpoints (for SDKs) ---

#[derive(serde::Deserialize)]
pub struct EvalShellRequest {
    pub command: String,
    #[serde(default = "default_tool_name")]
    pub tool_name: String,
    pub cwd: Option<String>,
}

fn default_tool_name() -> String {
    "Bash".into()
}

/// POST /api/evaluate/shell
pub async fn evaluate_shell(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvalShellRequest>,
) -> Json<serde_json::Value> {
    let ctx = ShellContext {
        command: req.command,
        tool_name: req.tool_name,
        cwd: req.cwd,
    };

    let engine = state.config.engine();
    let verdict = engine.evaluate_shell(&ctx);

    Json(serde_json::json!({
        "decision": format!("{:?}", verdict.decision).to_lowercase(),
        "reason": verdict.reason,
        "source": verdict.source,
    }))
}

#[derive(serde::Deserialize)]
pub struct EvalHttpRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// POST /api/evaluate/http
pub async fn evaluate_http(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EvalHttpRequest>,
) -> Json<serde_json::Value> {
    let parsed_url = match url::Url::parse(&req.url) {
        Ok(u) => u,
        Err(_) => match url::Url::parse(&format!("http://{}", req.url)) {
            Ok(u) => u,
            Err(e) => {
                return Json(serde_json::json!({
                    "decision": "deny",
                    "reason": format!("Invalid URL: {e}"),
                    "source": "builtin:api",
                }));
            }
        },
    };

    let host = parsed_url.host_str().unwrap_or("unknown").to_string();
    let port = parsed_url
        .port()
        .unwrap_or(if parsed_url.scheme() == "https" { 443 } else { 80 });
    let path = parsed_url.path().to_string();
    let content_type = req.headers.get("content-type").cloned();
    let body = req.body.map(|b| Bytes::from(b));

    let ctx = RequestContext {
        method: req.method,
        url: parsed_url,
        host,
        port,
        path,
        headers: req.headers,
        body,
        content_type,
    };

    let engine = state.config.engine();
    let verdict = engine.evaluate_http(&ctx).await;

    // Log the evaluation (no response data since this is a policy query, not a proxied request)
    let entry = AuditEntry::with_request(
        verdict.decision,
        verdict.reason.clone(),
        verdict.source.clone(),
        ctx.method.clone(),
        ctx.url.to_string(),
        ctx.host.clone(),
        Layer::Proxy,
        ctx.headers.clone(),
        ctx.body.as_deref(),
        ctx.content_type.clone(),
    );
    state.audit.log(&entry);

    Json(serde_json::json!({
        "decision": format!("{:?}", verdict.decision).to_lowercase(),
        "reason": verdict.reason,
        "source": verdict.source,
    }))
}

/// GET /api/secrets/status
pub async fn secrets_status(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    match state.config.secrets() {
        Some(secrets) => {
            let summary = secrets.status_summary();
            Json(serde_json::json!({
                "enabled": true,
                "rules": summary,
                "strip_env_count": secrets.strip_env.len(),
            }))
        }
        None => Json(serde_json::json!({
            "enabled": false,
            "rules": [],
            "strip_env_count": 0,
        })),
    }
}

// --- Snapshot API endpoints ---

#[derive(serde::Deserialize)]
pub struct SnapshotCreateRequest {
    /// Root directory to snapshot (defaults to current working directory)
    pub root: Option<String>,
}

/// POST /api/snapshot/create
pub async fn snapshot_create(
    State(state): State<Arc<AppState>>,
    body: Option<Json<SnapshotCreateRequest>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let root = body
        .and_then(|Json(req)| req.root.map(PathBuf::from))
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    if !state.snapshot_backend.is_available(&root) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Snapshot backend not available for this directory (no git repo?)"
            })),
        );
    }

    match state.snapshot_backend.create(&root) {
        Ok(info) => {
            let response = serde_json::json!({
                "id": info.id,
                "method": info.method,
                "root": info.root,
                "timestamp": info.timestamp,
            });
            state.snapshots.lock().await.insert(info.id.clone(), info);
            (StatusCode::OK, Json(response))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{e}") })),
        ),
    }
}

/// GET /api/snapshot/{id}/diff
pub async fn snapshot_diff(
    State(state): State<Arc<AppState>>,
    extract::Path(id): extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let snapshots = state.snapshots.lock().await;
    let Some(info) = snapshots.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Snapshot not found" })),
        );
    };

    match state.snapshot_backend.diff(info) {
        Ok(diff) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "added": diff.added,
                "modified": diff.modified,
                "deleted": diff.deleted,
                "summary": diff.summary,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{e}") })),
        ),
    }
}

/// POST /api/snapshot/{id}/rollback
pub async fn snapshot_rollback(
    State(state): State<Arc<AppState>>,
    extract::Path(id): extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut snapshots = state.snapshots.lock().await;
    let Some(info) = snapshots.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Snapshot not found" })),
        );
    };

    match state.snapshot_backend.rollback(info) {
        Ok(()) => {
            snapshots.remove(&id);
            (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{e}") })),
        ),
    }
}

#[derive(serde::Deserialize)]
pub struct SnapshotCommitRequest {
    pub message: Option<String>,
}

/// POST /api/snapshot/{id}/commit
pub async fn snapshot_commit(
    State(state): State<Arc<AppState>>,
    extract::Path(id): extract::Path<String>,
    body: Option<Json<SnapshotCommitRequest>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let message = body.and_then(|Json(req)| req.message);
    let mut snapshots = state.snapshots.lock().await;
    let Some(info) = snapshots.get(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Snapshot not found" })),
        );
    };

    match state.snapshot_backend.commit(info, message.as_deref()) {
        Ok(()) => {
            snapshots.remove(&id);
            (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{e}") })),
        ),
    }
}

// --- Replay endpoint ---

#[derive(serde::Deserialize)]
pub struct ReplayRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// POST /api/replay — Re-send a captured request, evaluate through policy, forward if allowed, log result.
pub async fn replay_request(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReplayRequest>,
) -> Json<serde_json::Value> {
    let parsed_url = match url::Url::parse(&req.url) {
        Ok(u) => u,
        Err(_) => match url::Url::parse(&format!("http://{}", req.url)) {
            Ok(u) => u,
            Err(e) => {
                return Json(serde_json::json!({
                    "decision": "deny",
                    "reason": format!("Invalid URL: {e}"),
                    "source": "builtin:api",
                }));
            }
        },
    };

    let host = parsed_url.host_str().unwrap_or("unknown").to_string();
    let port = parsed_url
        .port()
        .unwrap_or(if parsed_url.scheme() == "https" { 443 } else { 80 });
    let path = parsed_url.path().to_string();
    let content_type = req.headers.get("content-type").cloned();
    let body_bytes = req.body.as_ref().map(|b| Bytes::from(b.clone()));

    let ctx = RequestContext {
        method: req.method.clone(),
        url: parsed_url.clone(),
        host: host.clone(),
        port,
        path: path.clone(),
        headers: req.headers.clone(),
        body: body_bytes.clone(),
        content_type: content_type.clone(),
    };

    let engine = state.config.engine();
    let verdict = engine.evaluate_http(&ctx).await;

    let mut entry = AuditEntry::with_request(
        verdict.decision,
        verdict.reason.clone(),
        verdict.source.clone(),
        req.method.clone(),
        parsed_url.to_string(),
        host.clone(),
        Layer::Proxy,
        req.headers.clone(),
        body_bytes.as_deref(),
        content_type.clone(),
    );

    // If allowed, actually send the request and capture the response
    if verdict.decision == Decision::Allow {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();

        let method = match req.method.to_uppercase().as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "PATCH" => reqwest::Method::PATCH,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        };

        let mut request = client.request(method, parsed_url.as_str());
        for (k, v) in &req.headers {
            if k.to_lowercase() != "host" && k.to_lowercase() != "proxy-connection" {
                request = request.header(k.as_str(), v.as_str());
            }
        }
        if let Some(ref b) = req.body {
            request = request.body(b.clone());
        }

        match request.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_ct = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let mut resp_headers = HashMap::new();
                for (k, v) in resp.headers() {
                    if let Ok(val) = v.to_str() {
                        resp_headers.insert(k.to_string(), val.to_string());
                    }
                }
                let resp_body = resp.bytes().await.ok();
                entry.set_response(
                    status,
                    resp_headers.clone(),
                    resp_body.as_deref(),
                    resp_ct.as_deref(),
                );

                state.audit.log(&entry);

                return Json(serde_json::json!({
                    "decision": "allow",
                    "reason": verdict.reason,
                    "source": verdict.source,
                    "response": {
                        "status": status,
                        "headers": resp_headers,
                        "body": entry.response_body,
                    },
                    "entry": entry,
                }));
            }
            Err(e) => {
                state.audit.log(&entry);
                return Json(serde_json::json!({
                    "decision": "allow",
                    "reason": verdict.reason,
                    "source": verdict.source,
                    "error": format!("Request failed: {e}"),
                    "entry": entry,
                }));
            }
        }
    }

    // Denied — log and return
    state.audit.log(&entry);
    Json(serde_json::json!({
        "decision": format!("{:?}", verdict.decision).to_lowercase(),
        "reason": verdict.reason,
        "source": verdict.source,
        "entry": entry,
    }))
}

async fn handle_ws(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.audit.subscribe();

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(entry) => {
                        // Update stats
                        match entry.decision {
                            Decision::Allow => state.stats.record_allow(),
                            Decision::Deny => state.stats.record_deny(),
                        }

                        let msg = serde_json::json!({
                            "type": "event",
                            "data": entry,
                        });

                        if let Ok(json) = serde_json::to_string(&msg) {
                            if socket.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::debug!("WebSocket client lagged by {} events", n);
                    }
                    Err(_) => break,
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}
