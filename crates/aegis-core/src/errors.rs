use thiserror::Error;

#[derive(Debug, Error)]
pub enum AegisError {
    #[error("config error: {0}")]
    Config(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("scope error: {0}")]
    Scope(String),

    #[error("proxy error: {0}")]
    Proxy(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

pub type AegisResult<T> = Result<T, AegisError>;
