#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod fallback;

use tokio::process::Command;

use crate::config::ResolvedSandboxPolicy;
use crate::error::SandboxError;

/// Platform-specific sandbox backend.
pub trait SandboxBackend: Send + Sync {
    /// Create a command with sandbox restrictions applied.
    ///
    /// - **macOS**: wraps with `sandbox-exec -p '<profile>'`
    /// - **Linux**: applies Landlock via `pre_exec`
    /// - **Fallback**: returns the command unmodified with a warning
    fn sandboxed_command(
        &self,
        program: &str,
        args: &[String],
        policy: &ResolvedSandboxPolicy,
    ) -> Result<Command, SandboxError>;

    /// Human-readable description of the backend.
    fn describe(&self) -> String;

    /// Whether this backend is functional on the current system.
    fn is_available(&self) -> bool;
}

/// Detect the best available sandbox backend for the current platform.
pub fn detect_backend() -> Box<dyn SandboxBackend> {
    #[cfg(target_os = "macos")]
    {
        let backend = macos::SeatbeltBackend;
        if backend.is_available() {
            tracing::info!("Sandbox backend: macOS Seatbelt (sandbox-exec)");
            return Box::new(backend);
        }
    }

    #[cfg(target_os = "linux")]
    {
        let backend = linux::LandlockBackend;
        if backend.is_available() {
            tracing::info!("Sandbox backend: Linux Landlock");
            return Box::new(backend);
        }
    }

    tracing::warn!("No kernel sandbox available — using fallback (no isolation)");
    Box::new(fallback::FallbackBackend)
}
