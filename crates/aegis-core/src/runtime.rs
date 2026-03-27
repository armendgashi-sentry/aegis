//! Hot-reloadable runtime configuration.
//!
//! `RuntimeConfig` wraps the policy engine, secrets, and metadata behind `RwLock<Arc<T>>`
//! for atomic swap. The hot path (every request) does `read() → clone Arc → drop lock`
//! with nanosecond hold time. Config updates acquire a write lock briefly to swap the inner Arc.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use crate::audit::AuditLogger;
use crate::errors::{AegisError, AegisResult};
use crate::policy::PolicyEngine;
use crate::policy::yaml_policy::{RateLimitPolicy, YamlPolicy};
use crate::secrets::{SecretRule, SecretsConfig};

/// Shared, hot-reloadable configuration state.
///
/// Passed as `Arc<RuntimeConfig>` to proxy handler, guard server, web server, and TUI.
/// All reads are lock-free in practice (RwLock read + Arc clone).
pub struct RuntimeConfig {
    engine: RwLock<Arc<PolicyEngine>>,
    secrets: RwLock<Option<Arc<SecretsConfig>>>,
    policy_yaml: RwLock<YamlPolicy>,
    active_preset: RwLock<Option<String>>,
    policies_dir: PathBuf,
    middlewares_dir: PathBuf,
    secrets_path: RwLock<Option<PathBuf>>,
    audit: AuditLogger,
}

impl RuntimeConfig {
    /// Create a new RuntimeConfig by loading policies from disk.
    pub fn new(
        policies_dir: PathBuf,
        middlewares_dir: PathBuf,
        audit: AuditLogger,
        preset: Option<String>,
    ) -> AegisResult<Self> {
        let engine = PolicyEngine::from_policies(&policies_dir, &middlewares_dir, audit.clone())?;
        let policy_yaml = YamlPolicy::load_from_dir(&policies_dir)?;

        Ok(Self {
            engine: RwLock::new(Arc::new(engine)),
            secrets: RwLock::new(None),
            policy_yaml: RwLock::new(policy_yaml),
            active_preset: RwLock::new(preset),
            policies_dir,
            middlewares_dir,
            secrets_path: RwLock::new(None),
            audit,
        })
    }

    // --- Fast read accessors (hot path) ---

    /// Get the current policy engine. Clones the Arc under a brief read lock.
    pub fn engine(&self) -> Arc<PolicyEngine> {
        self.engine.read().unwrap().clone()
    }

    /// Get the current secrets config. Clones the Arc under a brief read lock.
    pub fn secrets(&self) -> Option<Arc<SecretsConfig>> {
        self.secrets.read().unwrap().clone()
    }

    /// Get a snapshot of the current YAML policy (for UI display).
    pub fn policy_snapshot(&self) -> YamlPolicy {
        self.policy_yaml.read().unwrap().clone()
    }

    /// Get the active preset name.
    pub fn active_preset(&self) -> Option<String> {
        self.active_preset.read().unwrap().clone()
    }

    /// Get the current rate limit policy.
    pub fn rate_limit(&self) -> RateLimitPolicy {
        self.policy_yaml.read().unwrap().rate_limit.clone()
    }

    /// Get the policies directory path.
    pub fn policies_dir(&self) -> &Path {
        &self.policies_dir
    }

    /// Get the audit logger (for replay logging).
    pub fn audit(&self) -> &AuditLogger {
        &self.audit
    }

    // --- Initial setup ---

    /// Set the secrets config (called once during startup).
    pub fn set_secrets(&self, secrets: SecretsConfig) {
        *self.secrets.write().unwrap() = Some(Arc::new(secrets));
    }

    /// Set the secrets file path (for persistence on updates).
    pub fn set_secrets_path(&self, path: PathBuf) {
        *self.secrets_path.write().unwrap() = Some(path);
    }

    // --- Config mutation (returns new RateLimitPolicy so caller can rebuild rate limiter) ---

    /// Apply a preset by name. Copies the preset YAML to the policies dir and rebuilds.
    /// Returns the new RateLimitPolicy so the caller can rebuild the rate limiter.
    pub fn apply_preset(&self, preset_name: &str) -> AegisResult<RateLimitPolicy> {
        let preset_path = self.policies_dir
            .parent()
            .unwrap_or(Path::new("."))
            .join("configs")
            .join("presets")
            .join(format!("{preset_name}.yaml"));

        // Also check relative to CWD
        let preset_path = if preset_path.exists() {
            preset_path
        } else {
            let alt = PathBuf::from(format!("configs/presets/{preset_name}.yaml"));
            if alt.exists() {
                alt
            } else {
                return Err(AegisError::Config(format!(
                    "Preset not found: {preset_name}"
                )));
            }
        };

        // Copy preset to policies dir
        let dest = self.policies_dir.join("default.yaml");
        std::fs::create_dir_all(&self.policies_dir)?;
        std::fs::copy(&preset_path, &dest)?;

        tracing::info!("Applied preset: {}", preset_name);
        *self.active_preset.write().unwrap() = Some(preset_name.to_string());

        self.rebuild_engine()
    }

    /// Update the full policy from a YamlPolicy struct. Persists to disk and rebuilds.
    /// Returns the new RateLimitPolicy.
    pub fn update_policy(&self, policy: YamlPolicy) -> AegisResult<RateLimitPolicy> {
        // Write to disk
        let yaml_str = serde_yaml::to_string(&policy)?;
        let dest = self.policies_dir.join("default.yaml");
        std::fs::create_dir_all(&self.policies_dir)?;
        std::fs::write(&dest, &yaml_str)?;

        tracing::info!("Policy updated and persisted to {}", dest.display());
        *self.active_preset.write().unwrap() = None; // custom config, no preset

        self.rebuild_engine()
    }

    /// Update only the rate limit section. Persists and rebuilds.
    /// Returns the new RateLimitPolicy.
    pub fn update_rate_limit(&self, rl: RateLimitPolicy) -> AegisResult<RateLimitPolicy> {
        let mut policy = self.policy_snapshot();
        policy.rate_limit = rl;
        self.update_policy(policy)
    }

    /// Replace the full secrets config. Persists to disk if a path is set.
    pub fn update_secrets(&self, secrets: SecretsConfig) -> AegisResult<()> {
        self.persist_secrets(&secrets)?;
        *self.secrets.write().unwrap() = Some(Arc::new(secrets));
        Ok(())
    }

    /// Add a single secret rule. Persists and swaps.
    pub fn add_secret(&self, rule: SecretRule) -> AegisResult<()> {
        let mut config = self.secrets()
            .map(|s| (*s).clone())
            .unwrap_or_default();

        // Replace if name already exists
        config.secrets.retain(|r| r.name != rule.name);
        config.secrets.push(rule);

        self.update_secrets(config)
    }

    /// Remove a secret rule by name. Persists and swaps.
    pub fn remove_secret(&self, name: &str) -> AegisResult<bool> {
        let mut config = self.secrets()
            .map(|s| (*s).clone())
            .unwrap_or_default();

        let before = config.secrets.len();
        config.secrets.retain(|r| r.name != name);
        let removed = config.secrets.len() < before;

        if removed {
            self.update_secrets(config)?;
        }
        Ok(removed)
    }

    /// Reload everything from disk. Returns the new RateLimitPolicy.
    pub fn reload_from_disk(&self) -> AegisResult<RateLimitPolicy> {
        // Reload secrets if path is set
        let secrets_path = self.secrets_path.read().unwrap().clone();
        if let Some(ref path) = secrets_path {
            if path.exists() {
                match SecretsConfig::load(path) {
                    Ok(s) => {
                        *self.secrets.write().unwrap() = Some(Arc::new(s));
                    }
                    Err(e) => tracing::warn!("Failed to reload secrets: {}", e),
                }
            }
        }

        self.rebuild_engine()
    }

    /// List available preset names from configs/presets/.
    pub fn list_presets(&self) -> Vec<String> {
        let presets_dir = PathBuf::from("configs/presets");
        if !presets_dir.exists() {
            return Vec::new();
        }

        let mut presets = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&presets_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                    if let Some(stem) = path.file_stem() {
                        let name = stem.to_string_lossy().to_string();
                        // Skip sandbox presets from the policy preset list
                        if !name.starts_with("sandbox-") {
                            presets.push(name);
                        }
                    }
                }
            }
        }
        presets.sort();
        presets
    }

    // --- Internal helpers ---

    /// Rebuild the PolicyEngine from disk and swap atomically.
    /// Returns the new RateLimitPolicy.
    fn rebuild_engine(&self) -> AegisResult<RateLimitPolicy> {
        let new_engine = PolicyEngine::from_policies(
            &self.policies_dir,
            &self.middlewares_dir,
            self.audit.clone(),
        )?;
        let new_yaml = YamlPolicy::load_from_dir(&self.policies_dir)?;
        let new_rl = new_yaml.rate_limit.clone();

        // Atomic swap
        *self.engine.write().unwrap() = Arc::new(new_engine);
        *self.policy_yaml.write().unwrap() = new_yaml;

        tracing::info!(
            "Policy engine reloaded: {} rps, burst {}, per_target={}",
            new_rl.requests_per_second,
            new_rl.burst,
            new_rl.per_target,
        );

        Ok(new_rl)
    }

    /// Persist secrets config to disk if a path is configured.
    fn persist_secrets(&self, secrets: &SecretsConfig) -> AegisResult<()> {
        let path = self.secrets_path.read().unwrap().clone();
        if let Some(ref path) = path {
            let yaml_str = serde_yaml::to_string(secrets)?;
            std::fs::write(path, &yaml_str).map_err(|e| {
                AegisError::Config(format!(
                    "Failed to write secrets to {}: {e}",
                    path.display()
                ))
            })?;
            tracing::info!("Secrets persisted to {}", path.display());
        }
        Ok(())
    }
}
