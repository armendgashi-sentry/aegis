use tokio::process::Command;

use crate::config::ResolvedSandboxPolicy;
use crate::error::SandboxError;

use super::SandboxBackend;

/// No-op sandbox backend — logs a warning and runs the command unsandboxed.
pub struct FallbackBackend;

impl SandboxBackend for FallbackBackend {
    fn sandboxed_command(
        &self,
        program: &str,
        args: &[String],
        _policy: &ResolvedSandboxPolicy,
    ) -> Result<Command, SandboxError> {
        tracing::warn!(
            "No sandbox backend available. The agent will run WITHOUT kernel isolation."
        );
        let mut cmd = Command::new(program);
        cmd.args(args);
        Ok(cmd)
    }

    fn describe(&self) -> String {
        "Fallback (no isolation)".into()
    }

    fn is_available(&self) -> bool {
        true
    }
}
