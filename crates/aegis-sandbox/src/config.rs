use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Sandbox isolation policy — controls what the child process can access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub filesystem: FilesystemPolicy,

    #[serde(default)]
    pub network: NetworkPolicy,

    #[serde(default)]
    pub process: ProcessPolicy,
}

/// Filesystem access restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Paths the agent can read (but not write). Resolved relative to CWD.
    #[serde(default = "default_read_only")]
    pub read_only: Vec<String>,

    /// Paths the agent can read and write. Resolved relative to CWD.
    #[serde(default = "default_read_write")]
    pub read_write: Vec<String>,

    /// Paths explicitly denied (overrides read_only/read_write).
    #[serde(default = "default_deny")]
    pub deny: Vec<String>,

    /// Allow access to system temp directory.
    #[serde(default = "default_true")]
    pub allow_tmp: bool,
}

/// Network access restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Allowed outbound connections as "host:port" or "*:port" patterns.
    #[serde(default)]
    pub allow_connect: Vec<String>,

    /// If true, deny all outbound network except explicit allows.
    #[serde(default)]
    pub deny_all: bool,
}

/// Process execution restrictions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessPolicy {
    /// Allow the sandboxed process to exec other programs.
    #[serde(default = "default_true")]
    pub allow_exec: bool,
}

// --- Defaults ---

fn default_true() -> bool {
    true
}

fn default_read_only() -> Vec<String> {
    vec![".".into()]
}

fn default_read_write() -> Vec<String> {
    vec![".".into()]
}

fn default_deny() -> Vec<String> {
    vec![
        "~/.ssh".into(),
        "~/.aws".into(),
        "~/.gnupg".into(),
    ]
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            process: ProcessPolicy::default(),
        }
    }
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            read_only: default_read_only(),
            read_write: default_read_write(),
            deny: default_deny(),
            allow_tmp: true,
        }
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allow_connect: vec![],
            deny_all: false,
        }
    }
}

impl Default for ProcessPolicy {
    fn default() -> Self {
        Self {
            allow_exec: true,
        }
    }
}

impl SandboxPolicy {
    /// Load a sandbox policy from a YAML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;

        // The YAML may have a top-level "sandbox:" key, or be the policy directly
        #[derive(Deserialize)]
        struct Wrapper {
            sandbox: Option<SandboxPolicy>,
        }

        if let Ok(wrapper) = serde_yaml::from_str::<Wrapper>(&content) {
            if let Some(policy) = wrapper.sandbox {
                return Ok(policy);
            }
        }

        Ok(serde_yaml::from_str(&content)?)
    }

    /// Resolve all paths in the policy to absolute paths.
    pub fn resolve_paths(&self, cwd: &Path) -> ResolvedSandboxPolicy {
        let resolve = |p: &str| -> PathBuf {
            if let Some(rest) = p.strip_prefix("~/") {
                if let Some(home) = dirs::home_dir() {
                    return home.join(rest);
                }
            }
            let path = PathBuf::from(p);
            if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            }
        };

        ResolvedSandboxPolicy {
            enabled: self.enabled,
            read_only: self.filesystem.read_only.iter().map(|p| resolve(p)).collect(),
            read_write: self.filesystem.read_write.iter().map(|p| resolve(p)).collect(),
            deny: self.filesystem.deny.iter().map(|p| resolve(p)).collect(),
            allow_tmp: self.filesystem.allow_tmp,
            allow_connect: self.network.allow_connect.clone(),
            deny_all_network: self.network.deny_all,
            allow_exec: self.process.allow_exec,
        }
    }
}

/// Sandbox policy with all paths resolved to absolute paths.
/// This is what the platform backends use.
#[derive(Debug, Clone)]
pub struct ResolvedSandboxPolicy {
    pub enabled: bool,
    pub read_only: Vec<PathBuf>,
    pub read_write: Vec<PathBuf>,
    pub deny: Vec<PathBuf>,
    pub allow_tmp: bool,
    pub allow_connect: Vec<String>,
    pub deny_all_network: bool,
    pub allow_exec: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_sane() {
        let policy = SandboxPolicy::default();
        assert!(policy.enabled);
        assert!(policy.filesystem.allow_tmp);
        assert!(policy.process.allow_exec);
        assert!(!policy.filesystem.deny.is_empty());
    }

    #[test]
    fn resolve_tilde_paths() {
        let policy = SandboxPolicy::default();
        let resolved = policy.resolve_paths(Path::new("/tmp/project"));

        // Deny paths should be resolved from ~
        for path in &resolved.deny {
            assert!(path.is_absolute(), "Deny path should be absolute: {:?}", path);
            assert!(!path.starts_with("~"), "Tilde should be expanded: {:?}", path);
        }
    }

    #[test]
    fn resolve_relative_paths() {
        let mut policy = SandboxPolicy::default();
        policy.filesystem.read_only = vec!["./src".into(), "tests".into()];
        let resolved = policy.resolve_paths(Path::new("/tmp/project"));

        assert_eq!(resolved.read_only[0], PathBuf::from("/tmp/project/./src"));
        assert_eq!(resolved.read_only[1], PathBuf::from("/tmp/project/tests"));
    }

    #[test]
    fn parse_yaml_with_sandbox_key() {
        let yaml = r#"
sandbox:
  enabled: true
  filesystem:
    read_only: ["."]
    read_write: ["./output"]
    deny: ["~/.ssh"]
    allow_tmp: true
  network:
    allow_connect: ["*:443"]
    deny_all: false
  process:
    allow_exec: true
"#;
        let tmp = std::env::temp_dir().join("aegis-test-sandbox.yaml");
        std::fs::write(&tmp, yaml).unwrap();
        let policy = SandboxPolicy::load(&tmp).unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.filesystem.read_write, vec!["./output"]);
        assert_eq!(policy.network.allow_connect, vec!["*:443"]);
        std::fs::remove_file(&tmp).ok();
    }
}
