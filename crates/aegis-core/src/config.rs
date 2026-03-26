use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::errors::AegisResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisConfig {
    #[serde(default = "default_proxy")]
    pub proxy: ProxyConfig,
    #[serde(default = "default_guard")]
    pub guard: GuardConfig,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub policies: PoliciesConfig,
    /// Path to secrets YAML file (e.g. "~/.config/aegis/secrets.yaml").
    #[serde(default)]
    pub secrets_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_listen")]
    pub listen: String,
    #[serde(default = "default_ca_cert")]
    pub ca_cert: String,
    #[serde(default = "default_ca_key")]
    pub ca_key: String,
    #[serde(default = "default_true")]
    pub auto_generate_ca: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    #[serde(default = "default_guard_listen")]
    pub listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_web_listen")]
    pub listen: String,
    #[serde(default = "default_static_dir")]
    pub static_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_log_file")]
    pub log_file: String,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoliciesConfig {
    #[serde(default = "default_policies_dir")]
    pub dir: String,
    #[serde(default = "default_middlewares_dir")]
    pub middlewares_dir: String,
}

// --- Defaults ---

fn default_proxy() -> ProxyConfig {
    ProxyConfig {
        listen: default_proxy_listen(),
        ca_cert: default_ca_cert(),
        ca_key: default_ca_key(),
        auto_generate_ca: true,
    }
}

fn default_guard() -> GuardConfig {
    GuardConfig {
        listen: default_guard_listen(),
    }
}

fn default_proxy_listen() -> String {
    "127.0.0.1:19000".into()
}

fn default_guard_listen() -> String {
    "127.0.0.1:19001".into()
}

fn default_web_listen() -> String {
    "127.0.0.1:19002".into()
}

fn default_ca_cert() -> String {
    "~/.config/aegis/ca.pem".into()
}

fn default_ca_key() -> String {
    "~/.config/aegis/ca-key.pem".into()
}

fn default_true() -> bool {
    true
}

fn default_static_dir() -> String {
    "./web".into()
}

fn default_log_file() -> String {
    "./aegis-audit.jsonl".into()
}

fn default_max_entries() -> usize {
    50_000
}

fn default_policies_dir() -> String {
    "./policies".into()
}

fn default_middlewares_dir() -> String {
    "./policies/middlewares".into()
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            proxy: default_proxy(),
            guard: default_guard(),
            web: WebConfig {
                listen: default_web_listen(),
                static_dir: default_static_dir(),
            },
            audit: AuditConfig {
                log_file: default_log_file(),
                max_entries: default_max_entries(),
            },
            policies: PoliciesConfig {
                dir: default_policies_dir(),
                middlewares_dir: default_middlewares_dir(),
            },
            secrets_file: None,
        }
    }
}

impl AegisConfig {
    /// Load config from a TOML file. Falls back to defaults if file doesn't exist.
    pub fn load(path: &Path) -> AegisResult<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Self = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    /// Expand `~` in paths to the user's home directory.
    pub fn expand_path(path: &str) -> PathBuf {
        if let Some(rest) = path.strip_prefix("~/") {
            if let Some(home) = dirs::home_dir() {
                return home.join(rest);
            }
        }
        PathBuf::from(path)
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen: default_web_listen(),
            static_dir: default_static_dir(),
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_file: default_log_file(),
            max_entries: default_max_entries(),
        }
    }
}

impl Default for PoliciesConfig {
    fn default() -> Self {
        Self {
            dir: default_policies_dir(),
            middlewares_dir: default_middlewares_dir(),
        }
    }
}
