use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use url::Url;

use aegis_core::analyzer::RequestContext;
use aegis_core::audit::{mask_secret_value, AuditEntry, AuditLogger, Layer, SecretApplied};
use aegis_core::decision::{Decision, Verdict};
use aegis_core::policy::yaml_policy::RateLimitPolicy;
use aegis_core::runtime::RuntimeConfig;

use crate::rate_limiter::ProxyRateLimiter;

/// The proxy handler: receives parsed requests and runs them through the policy engine.
pub struct ProxyHandler {
    pub config: Arc<RuntimeConfig>,
    pub rate_limiter: Arc<RwLock<ProxyRateLimiter>>,
    audit: AuditLogger,
    /// Addresses that bypass the policy engine (e.g., guard server, web UI).
    bypass: HashSet<String>,
}

impl ProxyHandler {
    pub fn new(
        config: Arc<RuntimeConfig>,
        rate_limiter: ProxyRateLimiter,
        audit: AuditLogger,
    ) -> Self {
        Self {
            config,
            rate_limiter: Arc::new(RwLock::new(rate_limiter)),
            audit,
            bypass: HashSet::new(),
        }
    }

    /// Add addresses that should bypass policy evaluation (e.g., "127.0.0.1:19001").
    pub fn with_bypass(mut self, addrs: Vec<String>) -> Self {
        self.bypass = addrs.into_iter().collect();
        self
    }

    /// Get a handle to the shared rate limiter (for web API to rebuild on config change).
    pub fn rate_limiter_handle(&self) -> Arc<RwLock<ProxyRateLimiter>> {
        self.rate_limiter.clone()
    }

    /// Rebuild the rate limiter with new policy values.
    pub fn rebuild_rate_limiter(&self, rl: &RateLimitPolicy) {
        let new = ProxyRateLimiter::new(rl.requests_per_second, rl.burst, rl.per_target);
        *self.rate_limiter.write().unwrap() = new;
        tracing::info!(
            "Rate limiter rebuilt: {} rps, burst {}, per_target={}",
            rl.requests_per_second, rl.burst, rl.per_target,
        );
    }

    /// Inject secret headers into a request's headers if a matching rule exists.
    /// Returns metadata about injected secrets (with masked values) for audit logging.
    pub fn inject_secrets(&self, host: &str, path: &str, headers: &mut HashMap<String, String>) -> Vec<SecretApplied> {
        let mut applied = Vec::new();
        if let Some(secrets) = self.config.secrets() {
            if let Some(rule) = secrets.find_match(host, path) {
                headers.insert(
                    rule.inject_header.to_lowercase(),
                    rule.inject_value.clone(),
                );
                tracing::debug!("[SECRET] Injected {} for rule '{}'", rule.inject_header, rule.name);
                applied.push(SecretApplied {
                    rule_name: rule.name.clone(),
                    header: rule.inject_header.to_lowercase(),
                    masked_value: mask_secret_value(&rule.inject_value),
                });
            }
        }
        applied
    }

    /// Check what secrets WOULD be applied (for audit metadata) without modifying headers.
    pub fn check_secrets_metadata(&self, host: &str, path: &str) -> Vec<SecretApplied> {
        let mut applied = Vec::new();
        if let Some(secrets) = self.config.secrets() {
            if let Some(rule) = secrets.find_match(host, path) {
                applied.push(SecretApplied {
                    rule_name: rule.name.clone(),
                    header: rule.inject_header.to_lowercase(),
                    masked_value: mask_secret_value(&rule.inject_value),
                });
            }
        }
        applied
    }

    /// Check if a host:port should bypass policy.
    pub fn is_bypass(&self, host: &str, port: u16) -> bool {
        let addr = format!("{host}:{port}");
        self.bypass.contains(&addr)
    }

    /// Evaluate a request. Returns the verdict and a prepared audit entry.
    /// The entry is NOT logged — the caller must set response data and call `log_entry()`.
    pub async fn evaluate(
        &self,
        method: &str,
        uri: &str,
        headers: HashMap<String, String>,
        body: Option<Bytes>,
    ) -> (Verdict, Option<AuditEntry>) {
        // Parse the URL
        let url = match Url::parse(uri) {
            Ok(u) => u,
            Err(_) => {
                match Url::parse(&format!("http://{uri}")) {
                    Ok(u) => u,
                    Err(_) => {
                        return (
                            Verdict::deny(
                                format!("Failed to parse request URL: {uri}"),
                                "builtin:proxy",
                            ),
                            None,
                        );
                    }
                }
            }
        };

        let host = url.host_str().unwrap_or("unknown").to_string();
        let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
        let path = url.path().to_string();
        let content_type = headers.get("content-type").cloned();

        // Bypass policy for Aegis's own services (guard, web UI)
        if self.is_bypass(&host, port) {
            return (Verdict::allow("bypass:aegis-internal"), None);
        }

        // Rate limit check (read lock on rate limiter)
        {
            let rl = self.rate_limiter.read().unwrap();
            if !rl.check(&host) {
                let verdict = Verdict::deny(
                    format!("Rate limit exceeded for target: {host}"),
                    "builtin:rate_limit",
                );
                let entry = AuditEntry::with_request(
                    verdict.decision,
                    verdict.reason.clone(),
                    verdict.source.clone(),
                    method.to_string(),
                    uri.to_string(),
                    host.clone(),
                    Layer::Proxy,
                    headers.clone(),
                    body.as_deref(),
                    content_type.clone(),
                );
                return (verdict, Some(entry));
            }
        }

        let ctx = RequestContext {
            method: method.to_string(),
            url,
            host: host.clone(),
            port,
            path: path.clone(),
            headers: headers.clone(),
            body: body.clone(),
            content_type: content_type.clone(),
        };

        let engine = self.config.engine();
        let verdict = engine.evaluate_http(&ctx).await;

        let secrets_applied = if verdict.decision == Decision::Allow {
            self.check_secrets_metadata(&host, &path)
        } else {
            Vec::new()
        };

        let mut entry = AuditEntry::with_request(
            verdict.decision,
            verdict.reason.clone(),
            verdict.source.clone(),
            method.to_string(),
            uri.to_string(),
            host,
            Layer::Proxy,
            headers,
            body.as_deref(),
            content_type,
        );
        entry.secrets_applied = secrets_applied;

        (verdict, Some(entry))
    }

    /// Log a finalized audit entry (after response data has been attached).
    pub fn log_entry(&self, entry: &AuditEntry) {
        self.audit.log(entry);
    }
}
