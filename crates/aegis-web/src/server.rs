use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

use aegis_core::audit::AuditLogger;
use aegis_core::policy::PolicyEngine;
use aegis_core::secrets::SecretsConfig;

use crate::routes;
use crate::state::AppState;

/// Start the web UI API server.
pub async fn start_web_server(
    listen_addr: SocketAddr,
    audit: AuditLogger,
    engine: Arc<PolicyEngine>,
    secrets: Option<Arc<SecretsConfig>>,
    static_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let state = Arc::new(AppState::new(audit, engine, secrets));

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
