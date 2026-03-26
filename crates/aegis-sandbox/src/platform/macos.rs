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
///
/// Strategy: `(deny default)` with broad capability allows + selective network.
/// In Seatbelt, deny always beats allow at equal specificity, so we use:
///   - `(deny default)` as the baseline
///   - Broad `(allow process*)(allow file*)(allow mach*)...` for non-network ops
///   - Selective `(allow network-outbound (remote tcp "localhost:<port>"))` for network
///   - Explicit `(deny file-read*)(deny file-write*)` for sensitive paths (these win
///     over the broad `(allow file*)` because deny beats allow)
fn generate_profile(policy: &ResolvedSandboxPolicy) -> Result<String, SandboxError> {
    let mut profile = String::new();

    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n");

    // --- Broad capability allows (everything except network) ---
    profile.push_str("\n;; Process, IPC, system capabilities\n");
    if policy.allow_exec {
        profile.push_str("(allow process*)\n");
    }
    profile.push_str("(allow signal)\n");
    profile.push_str("(allow sysctl*)\n");
    profile.push_str("(allow mach*)\n");
    profile.push_str("(allow ipc*)\n");
    profile.push_str("(allow system*)\n");

    // --- Filesystem: broad allow, then targeted denials ---
    profile.push_str("\n;; Filesystem (broad allow + targeted deny)\n");
    profile.push_str("(allow file*)\n");

    // Deny sensitive paths (deny beats allow in Seatbelt)
    if !policy.deny.is_empty() {
        profile.push_str("\n;; Denied filesystem paths\n");
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

    // --- Network: selective outbound only ---
    profile.push_str("\n;; Network isolation\n");
    if policy.deny_all_network && policy.allow_connect.is_empty() {
        // Complete network lockdown — deny default already covers this
        profile.push_str(";; All network denied\n");
    } else if policy.deny_all_network {
        // Selective network: only allow connections to specific ports.
        // DNS and local bind/inbound are needed for basic functionality.
        profile.push_str("(allow network-outbound (remote udp))\n");
        profile.push_str("(allow network-bind)\n");
        profile.push_str("(allow network-inbound)\n");
        for addr in &policy.allow_connect {
            // Seatbelt requires host to be "*" or "localhost" — convert 127.0.0.1
            let seatbelt_addr = addr
                .replace("127.0.0.1:", "localhost:")
                .replace("0.0.0.0:", "localhost:");
            profile.push_str(&format!(
                "(allow network-outbound (remote tcp \"{}\"))\n",
                seatbelt_addr
            ));
        }
    } else {
        // All network allowed — proxy handles enforcement
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
        assert!(profile.contains("(allow file*)"));
        assert!(profile.contains("(allow mach*)"));
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

        // deny default is the baseline; selective allows for specific ports
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:19000\"))"));
        // Should NOT have broad network allow
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn open_network_when_not_denied() {
        let policy = SandboxPolicy::default();
        let resolved = policy.resolve_paths(Path::new("/tmp/test"));
        let profile = generate_profile(&resolved).unwrap();

        // When network is not denied, broad network allow is present
        assert!(profile.contains("(allow network*)"));
    }
}
