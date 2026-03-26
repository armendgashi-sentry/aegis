use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::errors::AegisResult;
use crate::scope::TargetScope;

/// Top-level YAML policy structure. Loaded from one or more YAML files in the policies directory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct YamlPolicy {
    #[serde(default)]
    pub scope: TargetScope,
    #[serde(default)]
    pub http: HttpPolicy,
    #[serde(default)]
    pub shell: ShellPolicy,
    #[serde(default)]
    pub rate_limit: RateLimitPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpPolicy {
    #[serde(default = "default_methods")]
    pub methods: MethodPolicy,
    #[serde(default)]
    pub payload: PayloadPolicy,
    #[serde(default = "default_max_body")]
    pub max_request_body: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodPolicy {
    #[serde(default = "default_safe_methods")]
    pub safe: Vec<String>,
    #[serde(default = "default_inspect_methods")]
    pub inspect: Vec<String>,
    #[serde(default = "default_block_methods")]
    pub block: Vec<String>,
}

impl Default for MethodPolicy {
    fn default() -> Self {
        Self {
            safe: default_safe_methods(),
            inspect: default_inspect_methods(),
            block: default_block_methods(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadPolicy {
    #[serde(default = "default_block_sql")]
    pub block_sql: Vec<String>,
    #[serde(default = "default_allow_sql")]
    pub allow_sql: Vec<String>,
    #[serde(default = "default_block_commands")]
    pub block_commands: Vec<String>,
}

impl Default for PayloadPolicy {
    fn default() -> Self {
        Self {
            block_sql: default_block_sql(),
            allow_sql: default_allow_sql(),
            block_commands: default_block_commands(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellPolicy {
    #[serde(default = "default_shell_block_patterns")]
    pub block_patterns: Vec<String>,
    #[serde(default = "default_true")]
    pub block_sql_in_cli: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
    #[serde(default = "default_true")]
    pub per_target: bool,
}

// --- Defaults ---

fn default_methods() -> MethodPolicy {
    MethodPolicy {
        safe: default_safe_methods(),
        inspect: default_inspect_methods(),
        block: default_block_methods(),
    }
}

fn default_safe_methods() -> Vec<String> {
    vec!["GET".into(), "HEAD".into(), "OPTIONS".into(), "TRACE".into()]
}

fn default_inspect_methods() -> Vec<String> {
    vec!["POST".into(), "PUT".into(), "PATCH".into()]
}

fn default_block_methods() -> Vec<String> {
    vec!["DELETE".into()]
}

fn default_block_sql() -> Vec<String> {
    vec![
        "DROP".into(),
        "DELETE".into(),
        "TRUNCATE".into(),
        "ALTER TABLE".into(),
        "UPDATE".into(),
    ]
}

fn default_allow_sql() -> Vec<String> {
    vec!["SELECT".into(), "UNION".into(), "SHOW".into(), "DESCRIBE".into()]
}

fn default_block_commands() -> Vec<String> {
    vec![
        "rm -rf".into(),
        "rm -r".into(),
        "dd if=".into(),
        "mkfs".into(),
        "shutdown".into(),
        "reboot".into(),
    ]
}

fn default_shell_block_patterns() -> Vec<String> {
    vec![
        "rm -rf".into(),
        "rm -r".into(),
        "rmdir".into(),
        "dd if=".into(),
        "mkfs".into(),
        "shred".into(),
        "> /dev/".into(),
        "shutdown".into(),
        "reboot".into(),
    ]
}

fn default_true() -> bool {
    true
}

fn default_max_body() -> u64 {
    10_485_760 // 10MB
}

fn default_rps() -> u32 {
    10
}

fn default_burst() -> u32 {
    50
}

impl Default for HttpPolicy {
    fn default() -> Self {
        Self {
            methods: default_methods(),
            payload: PayloadPolicy::default(),
            max_request_body: default_max_body(),
        }
    }
}

impl Default for ShellPolicy {
    fn default() -> Self {
        Self {
            block_patterns: default_shell_block_patterns(),
            block_sql_in_cli: true,
        }
    }
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            requests_per_second: default_rps(),
            burst: default_burst(),
            per_target: true,
        }
    }
}

impl YamlPolicy {
    /// Load and merge all YAML policy files from a directory.
    pub fn load_from_dir(dir: &Path) -> AegisResult<Self> {
        if !dir.exists() {
            tracing::warn!("Policies directory not found: {}, using defaults", dir.display());
            return Ok(Self::default());
        }

        let mut merged = YamlPolicy::default();

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

            // Check which top-level keys are actually present in the YAML
            let raw: serde_yaml::Value = serde_yaml::from_str(&content)?;
            let map = raw.as_mapping();

            let policy: YamlPolicy = serde_yaml::from_str(&content)?;

            // Only merge sections that are explicitly present in the file
            let has_key = |key: &str| -> bool {
                map.is_some_and(|m| {
                    m.contains_key(&serde_yaml::Value::String(key.to_string()))
                })
            };

            if has_key("scope") && !policy.scope.targets.is_empty() {
                merged.scope = policy.scope;
            }
            if has_key("http") {
                merged.http = policy.http;
            }
            if has_key("shell") {
                merged.shell = policy.shell;
            }
            if has_key("rate_limit") {
                merged.rate_limit = policy.rate_limit;
            }
        }

        Ok(merged)
    }
}
