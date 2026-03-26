use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::decision::Decision;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Proxy,
    Guard,
}

/// Metadata about a secret that was injected into a request (values are masked).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretApplied {
    pub rule_name: String,
    pub header: String,
    pub masked_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub decision: Decision,
    pub reason: String,
    pub source: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub layer: Layer,
    /// HTTP request headers (empty for shell commands or older log entries).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub headers: std::collections::HashMap<String, String>,
    /// HTTP request body (truncated to 4KB for storage).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Content-Type of the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Secrets injected on this request (masked values, only for allowed requests).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets_applied: Vec<SecretApplied>,
}

/// Maximum body size stored in audit entries (4KB).
const MAX_BODY_LOG: usize = 4096;

impl AuditEntry {
    pub fn new(
        decision: Decision,
        reason: String,
        source: String,
        method: String,
        url: String,
        host: String,
        layer: Layer,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            decision,
            reason,
            source,
            method,
            url,
            host,
            layer,
            headers: std::collections::HashMap::new(),
            body: None,
            content_type: None,
            secrets_applied: Vec::new(),
        }
    }

    /// Create an audit entry with full HTTP request details.
    pub fn with_request(
        decision: Decision,
        reason: String,
        source: String,
        method: String,
        url: String,
        host: String,
        layer: Layer,
        headers: std::collections::HashMap<String, String>,
        body: Option<&[u8]>,
        content_type: Option<String>,
    ) -> Self {
        let body_str = body.and_then(|b| {
            std::str::from_utf8(b).ok().map(|s| {
                if s.len() > MAX_BODY_LOG {
                    format!("{}…[truncated, {} bytes total]", &s[..MAX_BODY_LOG], s.len())
                } else {
                    s.to_string()
                }
            })
        });

        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            decision,
            reason,
            source,
            method,
            url,
            host,
            layer,
            headers,
            body: body_str,
            content_type,
            secrets_applied: Vec::new(),
        }
    }
}

/// Mask a secret value for display: show first 3 and last 2 characters.
/// E.g., "Bearer sk-abc123xyz" → "Bea...yz"
pub fn mask_secret_value(value: &str) -> String {
    if value.len() <= 8 {
        "***".to_string()
    } else {
        format!("{}...{}", &value[..3], &value[value.len() - 2..])
    }
}

/// Audit logger that writes to JSONL file and broadcasts events for the web UI.
#[derive(Clone)]
pub struct AuditLogger {
    log_path: Option<String>,
    sender: broadcast::Sender<AuditEntry>,
}

impl AuditLogger {
    pub fn new(log_path: Option<String>) -> Self {
        let (sender, _) = broadcast::channel(1024);
        Self { log_path, sender }
    }

    /// Log an audit entry. Writes to file and broadcasts to subscribers.
    pub fn log(&self, entry: &AuditEntry) {
        // Write to JSONL file
        if let Some(ref path) = self.log_path {
            if let Ok(json) = serde_json::to_string(entry) {
                if let Ok(mut file) = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let _ = writeln!(file, "{json}");
                }
            }
        }

        // Broadcast to web UI subscribers (ignore if no receivers)
        let _ = self.sender.send(entry.clone());
    }

    /// Subscribe to live audit events (for web UI WebSocket / TUI).
    pub fn subscribe(&self) -> broadcast::Receiver<AuditEntry> {
        self.sender.subscribe()
    }

    /// Get the configured log file path.
    pub fn log_path(&self) -> Option<&str> {
        self.log_path.as_deref()
    }
}

/// Read an audit log file (JSONL format) and return parsed entries.
/// Invalid lines are silently skipped.
pub fn read_audit_log(path: &Path) -> anyhow::Result<Vec<AuditEntry>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

/// Find all JSONL audit log files in a directory, sorted by name (oldest first).
pub fn find_audit_logs(dir: &Path) -> Vec<PathBuf> {
    let mut logs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "jsonl") {
                logs.push(path);
            }
        }
    }
    // Sort by filename — since names include timestamps (aegis-YYYY-MM-DD_HH-MM-SS.jsonl),
    // this gives chronological order with newest last.
    logs.sort();
    logs
}

/// Find all tracing log files in a directory, sorted by name (oldest first).
pub fn find_tracing_logs(dir: &Path) -> Vec<PathBuf> {
    let mut logs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "log") {
                logs.push(path);
            }
        }
    }
    logs.sort();
    logs
}
