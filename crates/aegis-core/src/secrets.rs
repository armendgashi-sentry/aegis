//! Secret management: proxy-based credential injection.
//!
//! Secrets are stored outside the project directory (e.g. `~/.config/aegis/secrets.yaml`)
//! and injected as HTTP headers by the proxy on outbound requests.
//! The agent process never sees API keys in its environment or filesystem.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::errors::AegisResult;

/// Top-level secrets configuration loaded from a YAML file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// Secret injection rules: match host/path, inject header.
    #[serde(default)]
    pub secrets: Vec<SecretRule>,

    /// Environment variables to strip from the agent process.
    #[serde(default)]
    pub strip_env: Vec<String>,
}

/// A single secret injection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRule {
    /// Human-readable name for this secret (e.g. "github-api").
    pub name: String,

    /// Host glob pattern to match (e.g. "api.github.com", "*.internal.example.com").
    pub match_host: String,

    /// Optional path prefix to match (e.g. "/api/v2").
    #[serde(default)]
    pub match_path_prefix: Option<String>,

    /// Header name to inject (e.g. "Authorization", "X-API-Key").
    pub inject_header: String,

    /// Header value to inject (e.g. "Bearer ghp_xxxx").
    pub inject_value: String,
}

impl SecretsConfig {
    /// Load secrets from a YAML file.
    pub fn load(path: &Path) -> AegisResult<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            crate::errors::AegisError::Config(format!(
                "Failed to read secrets file {}: {e}",
                path.display()
            ))
        })?;
        let config: SecretsConfig = serde_yaml::from_str(&contents).map_err(|e| {
            crate::errors::AegisError::Config(format!(
                "Failed to parse secrets file {}: {e}",
                path.display()
            ))
        })?;
        tracing::info!(
            "Loaded {} secret rules from {}",
            config.secrets.len(),
            path.display()
        );
        Ok(config)
    }

    /// Find the first matching secret rule for a given host and path.
    pub fn find_match(&self, host: &str, path: &str) -> Option<&SecretRule> {
        self.secrets.iter().find(|rule| {
            if !matches_host_glob(host, &rule.match_host) {
                return false;
            }
            if let Some(ref prefix) = rule.match_path_prefix {
                if !path.starts_with(prefix) {
                    return false;
                }
            }
            true
        })
    }

    /// Return rule names and match patterns (no secret values) for status reporting.
    pub fn status_summary(&self) -> Vec<SecretStatus> {
        self.secrets
            .iter()
            .map(|r| SecretStatus {
                name: r.name.clone(),
                match_host: r.match_host.clone(),
                match_path_prefix: r.match_path_prefix.clone(),
                inject_header: r.inject_header.clone(),
            })
            .collect()
    }
}

/// Public status info for a secret rule (no values exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretStatus {
    pub name: String,
    pub match_host: String,
    pub match_path_prefix: Option<String>,
    pub inject_header: String,
}

/// Match a hostname against a glob pattern.
/// Supports "*.example.com" (wildcard) and exact match.
fn matches_host_glob(host: &str, pattern: &str) -> bool {
    let host = host.to_lowercase();
    let pattern = pattern.to_lowercase();

    if let Some(suffix) = pattern.strip_prefix("*.") {
        host == suffix || host.ends_with(&format!(".{suffix}"))
    } else {
        host == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SecretsConfig {
        SecretsConfig {
            secrets: vec![
                SecretRule {
                    name: "github".into(),
                    match_host: "api.github.com".into(),
                    match_path_prefix: None,
                    inject_header: "Authorization".into(),
                    inject_value: "Bearer ghp_test123".into(),
                },
                SecretRule {
                    name: "internal-api".into(),
                    match_host: "*.internal.example.com".into(),
                    match_path_prefix: Some("/api/v2".into()),
                    inject_header: "X-API-Key".into(),
                    inject_value: "key-secret456".into(),
                },
            ],
            strip_env: vec!["GITHUB_TOKEN".into(), "OPENAI_API_KEY".into()],
        }
    }

    #[test]
    fn exact_host_match() {
        let config = test_config();
        let rule = config.find_match("api.github.com", "/repos/foo");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().name, "github");
    }

    #[test]
    fn wildcard_host_match() {
        let config = test_config();
        let rule = config.find_match("app.internal.example.com", "/api/v2/users");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().name, "internal-api");
    }

    #[test]
    fn wildcard_host_no_path_match() {
        let config = test_config();
        // Host matches but path prefix doesn't
        let rule = config.find_match("app.internal.example.com", "/other/endpoint");
        assert!(rule.is_none());
    }

    #[test]
    fn no_match() {
        let config = test_config();
        assert!(config.find_match("api.openai.com", "/v1/chat").is_none());
    }

    #[test]
    fn case_insensitive_host() {
        let config = test_config();
        assert!(config.find_match("API.GitHub.Com", "/repos").is_some());
    }

    #[test]
    fn status_summary_hides_values() {
        let config = test_config();
        let summary = config.status_summary();
        assert_eq!(summary.len(), 2);
        assert_eq!(summary[0].name, "github");
        assert_eq!(summary[0].inject_header, "Authorization");
        // No inject_value field in SecretStatus
    }

    #[test]
    fn host_glob_matching() {
        assert!(matches_host_glob("api.github.com", "api.github.com"));
        assert!(!matches_host_glob("api.github.com", "github.com"));
        assert!(matches_host_glob("app.example.com", "*.example.com"));
        assert!(matches_host_glob("sub.app.example.com", "*.example.com"));
        assert!(matches_host_glob("example.com", "*.example.com"));
        assert!(!matches_host_glob("other.com", "*.example.com"));
    }
}
