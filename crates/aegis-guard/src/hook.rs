use serde::Serialize;

use aegis_core::decision::Decision;

/// Extract the tool name from a hook request body.
pub fn extract_tool_name(body: &serde_json::Value) -> Option<String> {
    body.get("tool_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract the shell command from a hook request body.
pub fn extract_command(body: &serde_json::Value) -> Option<String> {
    body.get("tool_input")
        .and_then(|ti| ti.get("command"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract the working directory from a hook request body.
pub fn extract_cwd(body: &serde_json::Value) -> Option<String> {
    body.get("cwd")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Claude Code hook response format.
#[derive(Debug, Clone, Serialize)]
pub struct ClaudeHookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: ClaudeHookDecision,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaudeHookDecision {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

/// Codex CLI hook response format.
#[derive(Debug, Clone, Serialize)]
pub struct CodexHookOutput {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ClaudeHookOutput {
    pub fn from_decision(decision: Decision, reason: &str) -> Self {
        Self {
            hook_specific_output: ClaudeHookDecision {
                hook_event_name: "PreToolUse".into(),
                permission_decision: match decision {
                    Decision::Allow => "allow".into(),
                    Decision::Deny => "deny".into(),
                },
                permission_decision_reason: if reason.is_empty() {
                    "Aegis: policy passed".to_string()
                } else {
                    format!("[AEGIS] {reason}")
                },
            },
        }
    }
}

impl CodexHookOutput {
    pub fn from_decision(decision: Decision, reason: &str) -> Self {
        Self {
            decision: match decision {
                Decision::Allow => "allow".into(),
                Decision::Deny => "block".into(),
            },
            reason: if reason.is_empty() {
                None
            } else {
                Some(format!("[AEGIS] {reason}"))
            },
        }
    }
}
