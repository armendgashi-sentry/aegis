use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Sandbox not available: {0}")]
    NotAvailable(String),

    #[error("Failed to apply sandbox: {0}")]
    ApplyFailed(String),

    #[error("Invalid sandbox config: {0}")]
    InvalidConfig(String),

    #[error("{0}")]
    Io(#[from] std::io::Error),
}
