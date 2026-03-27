use std::sync::Arc;

use axum::extract::{self, State};
use axum::http::StatusCode;
use axum::response::Json;

use aegis_core::policy::yaml_policy::{RateLimitPolicy, YamlPolicy};
use aegis_core::secrets::SecretRule;

use aegis_proxy::rate_limiter::ProxyRateLimiter;

use crate::state::AppState;

/// GET /api/config — full config snapshot
pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let policy = state.config.policy_snapshot();
    let preset = state.config.active_preset();
    let secrets_info = match state.config.secrets() {
        Some(s) => serde_json::json!({
            "enabled": true,
            "count": s.secrets.len(),
            "strip_env_count": s.strip_env.len(),
            "rules": s.status_summary(),
        }),
        None => serde_json::json!({
            "enabled": false,
            "count": 0,
            "strip_env_count": 0,
            "rules": [],
        }),
    };

    Json(serde_json::json!({
        "preset": preset,
        "policy": policy,
        "secrets": secrets_info,
        "available_presets": state.config.list_presets(),
    }))
}

/// GET /api/config/presets — list available preset names
pub async fn list_presets(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let presets = state.config.list_presets();
    let active = state.config.active_preset();
    Json(serde_json::json!({
        "presets": presets,
        "active": active,
    }))
}

#[derive(serde::Deserialize)]
pub struct ApplyPresetRequest {
    pub preset: String,
}

/// POST /api/config/presets/apply — apply a preset
pub async fn apply_preset(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ApplyPresetRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.config.apply_preset(&req.preset) {
        Ok(new_rl) => {
            // Rebuild rate limiter with new values
            rebuild_rate_limiter(&state, &new_rl);
            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "preset": req.preset,
                "rate_limit": new_rl,
            })))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": e.to_string(),
        }))),
    }
}

/// GET /api/config/policy — current policy as JSON
pub async fn get_policy(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let policy = state.config.policy_snapshot();
    Json(serde_json::to_value(policy).unwrap_or_default())
}

/// PUT /api/config/policy — update full policy
pub async fn update_policy(
    State(state): State<Arc<AppState>>,
    Json(policy): Json<YamlPolicy>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.config.update_policy(policy) {
        Ok(new_rl) => {
            rebuild_rate_limiter(&state, &new_rl);
            (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": e.to_string(),
        }))),
    }
}

/// PUT /api/config/rate-limit — update rate limit only
pub async fn update_rate_limit(
    State(state): State<Arc<AppState>>,
    Json(rl): Json<RateLimitPolicy>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.config.update_rate_limit(rl) {
        Ok(new_rl) => {
            rebuild_rate_limiter(&state, &new_rl);
            (StatusCode::OK, Json(serde_json::json!({
                "ok": true,
                "rate_limit": new_rl,
            })))
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": e.to_string(),
        }))),
    }
}

/// GET /api/config/secrets — secrets status (never expose values)
pub async fn get_secrets(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    match state.config.secrets() {
        Some(s) => Json(serde_json::json!({
            "enabled": true,
            "rules": s.status_summary(),
            "strip_env": s.strip_env,
        })),
        None => Json(serde_json::json!({
            "enabled": false,
            "rules": [],
            "strip_env": [],
        })),
    }
}

/// POST /api/config/secrets — add a secret rule
pub async fn add_secret(
    State(state): State<Arc<AppState>>,
    Json(rule): Json<SecretRule>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.config.add_secret(rule) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": e.to_string(),
        }))),
    }
}

/// DELETE /api/config/secrets/{name} — remove a secret rule
pub async fn remove_secret(
    State(state): State<Arc<AppState>>,
    extract::Path(name): extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.config.remove_secret(&name) {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({ "ok": true }))),
        Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": format!("Secret '{}' not found", name),
        }))),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": e.to_string(),
        }))),
    }
}

/// POST /api/config/reload — reload everything from disk
pub async fn reload_config(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.config.reload_from_disk() {
        Ok(new_rl) => {
            rebuild_rate_limiter(&state, &new_rl);
            (StatusCode::OK, Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": e.to_string(),
        }))),
    }
}

/// Helper: rebuild the proxy rate limiter if the web state has a handle to it.
fn rebuild_rate_limiter(state: &AppState, rl: &RateLimitPolicy) {
    if let Some(ref handle) = state.rate_limiter {
        let new = ProxyRateLimiter::new(rl.requests_per_second, rl.burst, rl.per_target);
        *handle.write().unwrap() = new;
        tracing::info!(
            "Rate limiter rebuilt: {} rps, burst {}, per_target={}",
            rl.requests_per_second, rl.burst, rl.per_target,
        );
    }
}
