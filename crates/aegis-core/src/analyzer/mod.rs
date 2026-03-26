pub mod http;
pub mod sql;
pub mod shell;

use std::collections::HashMap;

use bytes::Bytes;
use url::Url;

use crate::decision::Verdict;

/// Context for analyzing an HTTP request (proxy layer).
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub method: String,
    pub url: Url,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Bytes>,
    pub content_type: Option<String>,
}

/// Context for analyzing a shell command (guard layer).
#[derive(Debug, Clone)]
pub struct ShellContext {
    pub command: String,
    pub tool_name: String,
    pub cwd: Option<String>,
}

/// Analyzer for HTTP requests (proxy layer).
pub trait HttpAnalyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn analyze(&self, ctx: &RequestContext) -> Option<Verdict>;
}

/// Analyzer for shell commands (guard layer).
pub trait ShellAnalyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn analyze(&self, ctx: &ShellContext) -> Option<Verdict>;
}
