use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub decision: Decision,
    pub reason: String,
    /// Source of the verdict: "builtin:scope", "builtin:http", "builtin:sql",
    /// "policy:<filename>", "middleware:<name>"
    pub source: String,
}

impl Verdict {
    pub fn allow(source: impl Into<String>) -> Self {
        Self {
            decision: Decision::Allow,
            reason: String::new(),
            source: source.into(),
        }
    }

    pub fn deny(reason: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.into(),
            source: source.into(),
        }
    }

    pub fn is_deny(&self) -> bool {
        self.decision == Decision::Deny
    }
}
