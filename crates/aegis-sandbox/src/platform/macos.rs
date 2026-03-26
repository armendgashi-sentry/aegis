use std::path::PathBuf;

use tokio::process::Command;

use crate::config::ResolvedSandboxPolicy;
use crate::error::SandboxError;

use super::SandboxBackend;

/// macOS Seatbelt sandbox via `sandbox-exec -p '<profile>'`.
///
/// Generates a Sandbox Profile Language (SBPL) profile from the policy
/// and wraps the target command with `sandbox-exec`.
pub struct SeatbeltBackend;

impl SandboxBackend for SeatbeltBackend {
    fn sandboxed_command(
        &self,
        program: &str,
        args: &[String],
        policy: &ResolvedSandboxPolicy,
    ) -> Result<Command, SandboxError> {
        let profile = generate_profile(policy)?;
        tracing::debug!("Seatbelt profile:\n{}", profile);

        let mut cmd = Command::new("sandbox-exec");
        cmd.arg("-p").arg(&profile).arg(program).args(args);
        Ok(cmd)
    }

    fn describe(&self) -> String {
        "macOS Seatbelt (sandbox-exec)".into()
    }

    fn is_available(&self) -> bool {
        // sandbox-exec is available on macOS (though deprecated, still works)
        std::process::Command::new("sandbox-exec")
            .arg("-n")
            .arg("no-network")
            .arg("true")
            .output()
            .is_ok()
    }
}

/// Generate an SBPL profile string from the resolved sandbox policy.
fn generate_profile(policy: &ResolvedSandboxPolicy) -> Result<String, SandboxError> {
    let mut profile = String::new();

    // Header: deny everything by default
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");

    // --- Process ---
    if policy.allow_exec {
        profile.push_str("(allow process-exec)\n");
        profile.push_str("(allow process-fork)\n");
    }
    profile.push_str("(allow signal)\n");
    profile.push_str("(allow process-info*)\n");

    // --- System essentials (required for most programs to function) ---
    profile.push_str("\n;; System essentials\n");
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow mach-lookup)\n");
    profile.push_str("(allow mach-register)\n");
    profile.push_str("(allow ipc-posix-shm-read*)\n");
    profile.push_str("(allow ipc-posix-shm-write-create)\n");
    profile.push_str("(allow ipc-posix-shm-write-data)\n");

    // System libraries and binaries (read-only)
    profile.push_str("\n;; System read-only paths\n");
    for sys_path in &[
        "/usr", "/bin", "/sbin", "/Library", "/System",
        "/private/var/db", "/private/etc", "/etc",
        "/dev", "/var/run", "/var/folders",
    ] {
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            sys_path
        ));
    }

    // Allow reading the user's home essentials (shells, configs needed by tools)
    if let Some(home) = dirs::home_dir() {
        let home_str = home.display();
        for sub in &[".config", ".local", ".cargo", ".nvm", ".npm", ".rustup"] {
            let p = home.join(sub);
            if p.exists() {
                profile.push_str(&format!(
                    "(allow file-read* (subpath \"{}\"))\n",
                    p.display()
                ));
            }
        }
        // Shell rc files
        for rc in &[".zshrc", ".bashrc", ".profile", ".zprofile", ".bash_profile"] {
            profile.push_str(&format!(
                "(allow file-read* (literal \"{}/{}\"))\n",
                home_str, rc
            ));
        }
    }

    // --- Deny paths (before allow, so deny wins for overlapping paths) ---
    if !policy.deny.is_empty() {
        profile.push_str("\n;; Denied paths\n");
        for path in &policy.deny {
            let abs = canonicalize_or_keep(path);
            profile.push_str(&format!(
                "(deny file-read* (subpath \"{}\"))\n",
                abs.display()
            ));
            profile.push_str(&format!(
                "(deny file-write* (subpath \"{}\"))\n",
                abs.display()
            ));
        }
    }

    // --- Read-only paths ---
    if !policy.read_only.is_empty() {
        profile.push_str("\n;; Read-only paths\n");
        for path in &policy.read_only {
            let abs = canonicalize_or_keep(path);
            profile.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                abs.display()
            ));
        }
    }

    // --- Read-write paths ---
    if !policy.read_write.is_empty() {
        profile.push_str("\n;; Read-write paths\n");
        for path in &policy.read_write {
            let abs = canonicalize_or_keep(path);
            profile.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                abs.display()
            ));
            profile.push_str(&format!(
                "(allow file-write* (subpath \"{}\"))\n",
                abs.display()
            ));
        }
    }

    // --- Temp directory ---
    if policy.allow_tmp {
        profile.push_str("\n;; Temp directory\n");
        let tmp = std::env::temp_dir();
        profile.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            tmp.display()
        ));
        profile.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            tmp.display()
        ));
        // macOS also uses /private/tmp
        profile.push_str("(allow file-read* (subpath \"/private/tmp\"))\n");
        profile.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
    }

    // --- Network ---
    profile.push_str("\n;; Network\n");
    if policy.deny_all_network && policy.allow_connect.is_empty() {
        // Deny all network — nothing to add
        profile.push_str(";; All network denied\n");
    } else if policy.deny_all_network {
        // Only allow explicit connections
        profile.push_str("(allow network* (local udp))\n"); // DNS still needed
        profile.push_str("(allow network-outbound (remote udp \"*:53\"))\n");
        for addr in &policy.allow_connect {
            profile.push_str(&format!(
                "(allow network-outbound (remote tcp \"{}\"))\n",
                addr
            ));
        }
    } else {
        // Allow all network (proxy handles policy enforcement)
        profile.push_str("(allow network*)\n");
    }

    Ok(profile)
}

/// Try to canonicalize a path; if it doesn't exist yet, return it as-is.
fn canonicalize_or_keep(path: &PathBuf) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxPolicy;
    use std::path::Path;

    #[test]
    fn generates_valid_profile() {
        let policy = SandboxPolicy::default();
        let resolved = policy.resolve_paths(Path::new("/tmp/test-project"));
        let profile = generate_profile(&resolved).unwrap();

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow file-read*"));
        // Denied paths
        assert!(profile.contains(".ssh"));
    }

    #[test]
    fn deny_all_network_restricts_outbound() {
        let mut policy = SandboxPolicy::default();
        policy.network.deny_all = true;
        policy.network.allow_connect = vec!["127.0.0.1:19000".into()];

        let resolved = policy.resolve_paths(Path::new("/tmp/test"));
        let profile = generate_profile(&resolved).unwrap();

        assert!(profile.contains("(allow network-outbound (remote tcp \"127.0.0.1:19000\"))"));
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn open_network_when_not_denied() {
        let policy = SandboxPolicy::default();
        let resolved = policy.resolve_paths(Path::new("/tmp/test"));
        let profile = generate_profile(&resolved).unwrap();

        assert!(profile.contains("(allow network*)"));
    }
}
