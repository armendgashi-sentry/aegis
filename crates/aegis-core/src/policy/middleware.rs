use std::path::Path;
use std::process::Stdio;

use serde::{Deserialize, Serialize};

use crate::analyzer::RequestContext;
use crate::decision::Verdict;
use crate::errors::AegisResult;

/// A custom middleware definition loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiddlewareDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub trigger: MiddlewareTrigger,
    pub action: MiddlewareAction,
    #[serde(default)]
    pub reason: String,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MiddlewareTrigger {
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_matches: Option<String>,
    #[serde(default)]
    pub content_types: Vec<String>,
    #[serde(default)]
    pub header_contains: Option<HeaderMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderMatch {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MiddlewareAction {
    Block,
    Script { command: String },
}

fn default_timeout() -> u64 {
    3000
}

/// Engine that evaluates custom middlewares against requests.
pub struct MiddlewareEngine {
    middlewares: Vec<MiddlewareDef>,
}

impl MiddlewareEngine {
    pub fn new(middlewares: Vec<MiddlewareDef>) -> Self {
        Self { middlewares }
    }

    /// Load all middleware YAML files from a directory.
    pub fn load_from_dir(dir: &Path) -> AegisResult<Self> {
        let mut middlewares = Vec::new();

        if !dir.exists() {
            return Ok(Self::new(middlewares));
        }

        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext == "yaml" || ext == "yml")
            })
            .collect();

        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let content = std::fs::read_to_string(entry.path())?;
            let mw: MiddlewareDef = serde_yaml::from_str(&content)?;
            tracing::info!("Loaded middleware: {} ({})", mw.name, entry.path().display());
            middlewares.push(mw);
        }

        Ok(Self::new(middlewares))
    }

    /// Evaluate all middlewares against a request.
    pub async fn evaluate(&self, ctx: &RequestContext) -> Option<Verdict> {
        for mw in &self.middlewares {
            if !self.triggers_match(mw, ctx) {
                continue;
            }

            match &mw.action {
                MiddlewareAction::Block => {
                    let reason = if mw.reason.is_empty() {
                        format!("Blocked by middleware: {}", mw.name)
                    } else {
                        mw.reason.clone()
                    };
                    return Some(Verdict::deny(reason, format!("middleware:{}", mw.name)));
                }
                MiddlewareAction::Script { command } => {
                    match self.run_script(command, ctx, mw.timeout_ms).await {
                        ScriptResult::Allow => continue,
                        ScriptResult::Block(reason) => {
                            return Some(Verdict::deny(
                                reason,
                                format!("middleware:{}", mw.name),
                            ));
                        }
                        ScriptResult::Error(err) => {
                            tracing::warn!(
                                "Middleware {} script error: {}. Allowing request.",
                                mw.name,
                                err,
                            );
                            continue;
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if a middleware's trigger conditions match the request.
    fn triggers_match(&self, mw: &MiddlewareDef, ctx: &RequestContext) -> bool {
        let trigger = &mw.trigger;

        // Check methods
        if !trigger.methods.is_empty()
            && !trigger
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&ctx.method))
        {
            return false;
        }

        // Check path pattern
        if let Some(ref pattern) = trigger.path_matches {
            if !self.path_matches(&ctx.path, pattern) {
                return false;
            }
        }

        // Check content type
        if !trigger.content_types.is_empty() {
            let ct = ctx.content_type.as_deref().unwrap_or("");
            if !trigger.content_types.iter().any(|t| ct.contains(t)) {
                return false;
            }
        }

        // Check header
        if let Some(ref header_match) = trigger.header_contains {
            let header_val = ctx
                .headers
                .get(&header_match.name.to_lowercase())
                .map(|s| s.as_str())
                .unwrap_or("");
            if !header_val.contains(&header_match.value) {
                return false;
            }
        }

        true
    }

    /// Simple glob-like path matching.
    /// "/admin/*" matches "/admin/users", "/admin/settings/foo"
    fn path_matches(&self, path: &str, pattern: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix("/*") {
            path.starts_with(prefix) && path.len() > prefix.len()
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path == pattern
        }
    }

    /// Run a script-based middleware. Sends request context as JSON on stdin.
    /// Exit 0 = allow, Exit 2 = block (reason on stderr).
    async fn run_script(
        &self,
        command: &str,
        ctx: &RequestContext,
        timeout_ms: u64,
    ) -> ScriptResult {
        let input = serde_json::json!({
            "method": ctx.method,
            "url": ctx.url.to_string(),
            "host": ctx.host,
            "port": ctx.port,
            "path": ctx.path,
            "headers": ctx.headers,
            "body": ctx.body.as_ref().and_then(|b| std::str::from_utf8(b).ok()),
        });

        let input_str = match serde_json::to_string(&input) {
            Ok(s) => s,
            Err(e) => return ScriptResult::Error(format!("Failed to serialize context: {e}")),
        };

        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return ScriptResult::Error("Empty script command".into());
        }

        let mut cmd = tokio::process::Command::new(parts[0]);
        if parts.len() > 1 {
            cmd.args(&parts[1..]);
        }

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return ScriptResult::Error(format!("Failed to spawn script: {e}")),
        };

        // Write input to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(input_str.as_bytes()).await;
            drop(stdin);
        }

        // Wait with timeout
        let timeout = tokio::time::Duration::from_millis(timeout_ms);
        match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => match output.status.code() {
                Some(0) => ScriptResult::Allow,
                Some(2) => {
                    let reason = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    ScriptResult::Block(if reason.is_empty() {
                        "Blocked by script middleware".into()
                    } else {
                        reason
                    })
                }
                Some(code) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    ScriptResult::Error(format!("Script exited with code {code}: {stderr}"))
                }
                None => ScriptResult::Error("Script killed by signal".into()),
            },
            Ok(Err(e)) => ScriptResult::Error(format!("Script execution error: {e}")),
            Err(_) => {
                // Timeout - process already consumed by wait_with_output, just report
                ScriptResult::Error("Script timed out".into())
            }
        }
    }
}

enum ScriptResult {
    Allow,
    Block(String),
    Error(String),
}
