use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::post;
use axum::Router;

use aegis_core::analyzer::ShellContext;
use aegis_core::decision::Decision;
use aegis_core::policy::PolicyEngine;

use crate::hook;

struct GuardState {
    engine: Arc<PolicyEngine>,
}

/// Start the shell guard HTTP server.
pub async fn start_guard_server(
    listen_addr: SocketAddr,
    engine: Arc<PolicyEngine>,
) -> anyhow::Result<()> {
    let state = Arc::new(GuardState { engine });

    let app = Router::new()
        .route("/hook", post(handle_hook))
        .route("/hook/claude", post(handle_hook_claude))
        .route("/hook/codex", post(handle_hook_codex))
        .fallback(handle_fallback)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!("Aegis guard listening on {}", listen_addr);

    axum::serve(listener, app).await?;
    Ok(())
}

/// Generic hook handler — accepts raw bytes, parses JSON manually for maximum compatibility.
/// Defaults to Claude Code response format.
async fn handle_hook(
    State(state): State<Arc<GuardState>>,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    tracing::info!("Guard hook received {} bytes", body.len());

    let (decision, reason) = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(json) => {
            tracing::info!("Guard hook payload: tool={}, event={}",
                json.get("tool_name").and_then(|v| v.as_str()).unwrap_or("?"),
                json.get("hook_event_name").and_then(|v| v.as_str()).unwrap_or("?"),
            );
            evaluate_hook(&state.engine, &json)
        }
        Err(e) => {
            tracing::warn!("Guard hook: failed to parse JSON: {}", e);
            tracing::warn!("Guard hook raw body: {:?}", String::from_utf8_lossy(&body));
            (Decision::Allow, String::new())
        }
    };

    let response = serde_json::to_value(hook::ClaudeHookOutput::from_decision(decision, &reason)).unwrap();
    tracing::info!("Guard hook response: decision={:?}, reason={}", decision, if reason.is_empty() { "policy passed" } else { &reason });
    (StatusCode::OK, Json(response))
}

/// Claude Code specific hook handler.
async fn handle_hook_claude(
    State(state): State<Arc<GuardState>>,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    tracing::info!("Guard hook (claude) received {} bytes", body.len());

    let (decision, reason) = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(json) => {
            tracing::info!("Guard hook (claude) payload: tool={}, event={}",
                json.get("tool_name").and_then(|v| v.as_str()).unwrap_or("?"),
                json.get("hook_event_name").and_then(|v| v.as_str()).unwrap_or("?"),
            );
            evaluate_hook(&state.engine, &json)
        }
        Err(e) => {
            tracing::warn!("Guard hook (claude): failed to parse JSON: {}", e);
            (Decision::Allow, String::new())
        }
    };

    let response = serde_json::to_value(hook::ClaudeHookOutput::from_decision(decision, &reason)).unwrap();
    tracing::info!("Guard hook (claude) response: decision={:?}", decision);
    (StatusCode::OK, Json(response))
}

/// Codex CLI specific hook handler.
async fn handle_hook_codex(
    State(state): State<Arc<GuardState>>,
    body: Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let (decision, reason) = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(json) => {
            tracing::debug!("Guard hook (codex) received: {}", json);
            evaluate_hook(&state.engine, &json)
        }
        Err(e) => {
            tracing::warn!("Guard hook (codex): failed to parse JSON: {}", e);
            (Decision::Allow, String::new())
        }
    };

    let output = hook::CodexHookOutput::from_decision(decision, &reason);
    (StatusCode::OK, Json(serde_json::to_value(output).unwrap()))
}

/// Catch-all handler: logs unexpected requests to help debug hook routing issues.
async fn handle_fallback(req: axum::extract::Request) -> (StatusCode, &'static str) {
    tracing::warn!(
        "Guard received unexpected request: {} {}",
        req.method(),
        req.uri()
    );
    (StatusCode::NOT_FOUND, "Not found")
}

fn evaluate_hook(engine: &PolicyEngine, body: &serde_json::Value) -> (Decision, String) {
    let tool_name = hook::extract_tool_name(body).unwrap_or_default();

    // For Bash/shell tools, analyze the command
    if tool_name == "Bash" || tool_name == "shell" || tool_name == "Terminal" {
        if let Some(command) = hook::extract_command(body) {
            let ctx = ShellContext {
                command,
                tool_name: tool_name.clone(),
                cwd: hook::extract_cwd(body),
            };

            tracing::debug!("Guard evaluating shell command: {:?}", ctx.command);
            let verdict = engine.evaluate_shell(&ctx);

            if verdict.is_deny() {
                tracing::warn!(
                    "[GUARD BLOCKED] {} -> {} ({})",
                    ctx.command, verdict.reason, verdict.source
                );
            } else {
                tracing::debug!("[GUARD ALLOWED] {}", ctx.command);
            }

            return (verdict.decision, verdict.reason);
        }
    }

    // Allow all non-shell tools
    tracing::debug!("Guard allowing non-shell tool: {}", tool_name);
    (Decision::Allow, String::new())
}
