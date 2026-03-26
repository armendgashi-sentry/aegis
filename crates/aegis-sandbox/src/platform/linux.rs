use std::os::unix::process::CommandExt;
use std::path::PathBuf;

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use tokio::process::Command;

use crate::config::ResolvedSandboxPolicy;
use crate::error::SandboxError;

use super::SandboxBackend;

/// Linux Landlock sandbox — unprivileged, kernel 5.13+.
///
/// Applied via `pre_exec`: runs after fork, before exec.
/// The parent process is never restricted.
pub struct LandlockBackend;

impl SandboxBackend for LandlockBackend {
    fn sandboxed_command(
        &self,
        program: &str,
        args: &[String],
        policy: &ResolvedSandboxPolicy,
    ) -> Result<Command, SandboxError> {
        // Prepare rules: open file descriptors now (before fork).
        // They'll be inherited by the child and used in pre_exec.
        let rules = prepare_rules(policy)?;

        let mut cmd = Command::new(program);
        cmd.args(args);

        let allow_exec = policy.allow_exec;

        unsafe {
            cmd.pre_exec(move || {
                apply_landlock(&rules, allow_exec).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                })
            });
        }

        Ok(cmd)
    }

    fn describe(&self) -> String {
        let abi = best_abi();
        format!("Linux Landlock (ABI v{})", abi as u32)
    }

    fn is_available(&self) -> bool {
        // Try to create a minimal ruleset — if it fails, Landlock isn't supported
        Ruleset::default()
            .handle_access(AccessFs::from_all(ABI::V1))
            .is_ok()
    }
}

/// A pre-opened file descriptor with its access rights.
struct PreparedRule {
    path: PathBuf,
    fd: PathFd,
    read_only: bool,
}

// PathFd contains an OwnedFd which is Send
unsafe impl Send for PreparedRule {}
unsafe impl Sync for PreparedRule {}

fn best_abi() -> ABI {
    // Try from newest to oldest
    for abi in [ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1] {
        if Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .is_ok()
        {
            return abi;
        }
    }
    ABI::V1
}

fn prepare_rules(policy: &ResolvedSandboxPolicy) -> Result<Vec<PreparedRule>, SandboxError> {
    let mut rules = Vec::new();

    // System read-only paths
    let system_paths = [
        "/usr", "/lib", "/lib64", "/bin", "/sbin",
        "/etc", "/dev", "/proc", "/sys",
    ];
    for path in &system_paths {
        let p = PathBuf::from(path);
        if p.exists() {
            match PathFd::new(&p) {
                Ok(fd) => rules.push(PreparedRule { path: p, fd, read_only: true }),
                Err(e) => tracing::debug!("Skipping system path {}: {}", path, e),
            }
        }
    }

    // Policy read-only paths
    for path in &policy.read_only {
        if path.exists() {
            match PathFd::new(path) {
                Ok(fd) => rules.push(PreparedRule {
                    path: path.clone(),
                    fd,
                    read_only: true,
                }),
                Err(e) => tracing::warn!("Cannot open read-only path {:?}: {}", path, e),
            }
        }
    }

    // Policy read-write paths
    for path in &policy.read_write {
        if path.exists() {
            match PathFd::new(path) {
                Ok(fd) => rules.push(PreparedRule {
                    path: path.clone(),
                    fd,
                    read_only: false,
                }),
                Err(e) => tracing::warn!("Cannot open read-write path {:?}: {}", path, e),
            }
        }
    }

    // Tmp directory
    if policy.allow_tmp {
        let tmp = std::env::temp_dir();
        if tmp.exists() {
            if let Ok(fd) = PathFd::new(&tmp) {
                rules.push(PreparedRule {
                    path: tmp,
                    fd,
                    read_only: false,
                });
            }
        }
    }

    Ok(rules)
}

fn apply_landlock(rules: &[PreparedRule], allow_exec: bool) -> Result<(), SandboxError> {
    let abi = best_abi();
    let all_access = AccessFs::from_all(abi);
    let read_access = AccessFs::from_read(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(all_access)
        .map_err(|e| SandboxError::ApplyFailed(format!("handle_access: {e}")))?
        .create()
        .map_err(|e| SandboxError::ApplyFailed(format!("create ruleset: {e}")))?;

    for rule in rules {
        let access = if rule.read_only {
            if allow_exec {
                read_access | AccessFs::Execute
            } else {
                read_access
            }
        } else {
            all_access
        };

        ruleset = ruleset
            .add_rule(PathBeneath::new(&rule.fd, access))
            .map_err(|e| {
                SandboxError::ApplyFailed(format!(
                    "add_rule for {:?}: {e}",
                    rule.path
                ))
            })?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::ApplyFailed(format!("restrict_self: {e}")))?;

    tracing::info!(
        "Landlock applied: {} rules, status: {:?}",
        rules.len(),
        status.ruleset
    );

    Ok(())
}
