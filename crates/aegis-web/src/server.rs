use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

use aegis_core::audit::AuditLogger;
use aegis_core::runtime::RuntimeConfig;
use aegis_proxy::rate_limiter::ProxyRateLimiter;

use crate::config_routes;
use crate::routes;
use crate::state::AppState;

/// Start the web UI API server.
pub async fn start_web_server(
    listen_addr: SocketAddr,
    audit: AuditLogger,
    config: Arc<RuntimeConfig>,
    rate_limiter: Option<Arc<RwLock<ProxyRateLimiter>>>,
    static_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let state = Arc::new(AppState::new(audit, config, rate_limiter));

    let mut app = Router::new()
        .route("/api/health", get(routes::health))
        .route("/api/stats", get(routes::get_stats))
        .route("/api/logs", get(routes::list_logs))
        .route("/api/logs/entries", get(routes::get_log_entries))
        .route("/api/live", get(routes::live_events))
        .route("/api/evaluate/shell", post(routes::evaluate_shell))
        .route("/api/evaluate/http", post(routes::evaluate_http))
        .route("/api/secrets/status", get(routes::secrets_status))
        // Snapshot endpoints
        .route("/api/snapshot/create", post(routes::snapshot_create))
        .route("/api/snapshot/{id}/diff", get(routes::snapshot_diff))
        .route("/api/snapshot/{id}/rollback", post(routes::snapshot_rollback))
        .route("/api/snapshot/{id}/commit", post(routes::snapshot_commit))
        // Config management endpoints
        .route("/api/config", get(config_routes::get_config))
        .route("/api/config/presets", get(config_routes::list_presets))
        .route("/api/config/presets/apply", post(config_routes::apply_preset))
        .route("/api/config/policy", get(config_routes::get_policy).put(config_routes::update_policy))
        .route("/api/config/rate-limit", put(config_routes::update_rate_limit))
        .route("/api/config/secrets", get(config_routes::get_secrets).post(config_routes::add_secret))
        .route("/api/config/secrets/{name}", delete(config_routes::remove_secret))
        .route("/api/config/reload", post(config_routes::reload_config))
        .with_state(state);

    // Serve the SPA static files if a directory is provided
    if let Some(dir) = static_dir {
        if dir.exists() {
            let index = dir.join("index.html");
            // Fallback to index.html for SPA routing
            let serve_dir = ServeDir::new(&dir).fallback(ServeFile::new(index));
            app = app.fallback_service(serve_dir);
            tracing::info!("Serving web UI from {}", dir.display());
        } else {
            tracing::warn!("Static dir {} does not exist, skipping SPA serving", dir.display());
        }
    }

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!("Aegis web UI listening on http://{}", listen_addr);

    axum::serve(listener, app).await?;
    Ok(())
}
