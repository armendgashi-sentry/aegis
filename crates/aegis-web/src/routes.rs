use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{self, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use bytes::Bytes;

use aegis_core::analyzer::{RequestContext, ShellContext};
use aegis_core::audit;
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
    pub decision: Option<String>,
}

/// GET /api/logs/entries?file=<path>&limit=N&decision=allow|deny
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

    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|entry| {
            if let Some(ref d) = query.decision {
                match d.as_str() {
                    "allow" => entry.decision == Decision::Allow,
                    "deny" => entry.decision == Decision::Deny,
                    _ => true,
                }
            } else {
                true
            }
        })
        .collect();

    let limited = match query.limit {
        Some(n) => &filtered[..n.min(filtered.len())],
        None => &filtered,
    };

    let total = filtered.len();
    let allowed = filtered.iter().filter(|e| e.decision == Decision::Allow).count();
    let denied = filtered.iter().filter(|e| e.decision == Decision::Deny).count();

    Json(serde_json::json!({
        "entries": limited,
        "stats": {
            "total": total,
            "allowed": allowed,
            "denied": denied,
        }
    }))
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

    let verdict = state.engine.evaluate_shell(&ctx);

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

    let verdict = state.engine.evaluate_http(&ctx).await;

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
    match &state.secrets {
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
