use std::path::PathBuf;
use std::sync::OnceLock;

use chrono::Local;

/// Process-wide session ID, generated once on first access.
static SESSION_ID: OnceLock<String> = OnceLock::new();

/// Default log directory relative to the working directory.
pub const LOG_DIR: &str = "logs";

/// Get the session ID for this process (e.g., "2026-03-25_01-15-30").
pub fn session_id() -> &'static str {
    SESSION_ID.get_or_init(|| Local::now().format("%Y-%m-%d_%H-%M-%S").to_string())
}

/// Get the path for the tracing log file for this session.
pub fn tracing_log_path() -> PathBuf {
    PathBuf::from(LOG_DIR).join(format!("aegis-{}.log", session_id()))
}

/// Get the path for the audit (JSONL) log file for this session.
pub fn audit_log_path() -> PathBuf {
    PathBuf::from(LOG_DIR).join(format!("aegis-{}.jsonl", session_id()))
}

/// Ensure the log directory exists.
pub fn ensure_log_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(LOG_DIR)
}
