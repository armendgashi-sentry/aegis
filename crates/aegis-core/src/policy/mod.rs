pub mod yaml_policy;
pub mod middleware;

use std::path::Path;
use crate::analyzer::http::BuiltinHttpAnalyzer;
use crate::analyzer::shell::ShellCommandAnalyzer;
use crate::analyzer::sql::SqlAnalyzer;
use crate::analyzer::{HttpAnalyzer, RequestContext, ShellAnalyzer, ShellContext};
use crate::audit::{AuditEntry, AuditLogger, Layer};
use crate::decision::Verdict;
use crate::errors::AegisResult;
use crate::scope::TargetScope;

use self::middleware::MiddlewareEngine;
use self::yaml_policy::YamlPolicy;

/// The policy engine runs all analyzers and middlewares, producing a final verdict.
/// Uses deny-first: any Deny from any source = request blocked.
pub struct PolicyEngine {
    scope: TargetScope,
    http_analyzers: Vec<Box<dyn HttpAnalyzer>>,
    shell_analyzers: Vec<Box<dyn ShellAnalyzer>>,
    middleware_engine: MiddlewareEngine,
    audit: AuditLogger,
}

impl PolicyEngine {
    /// Build the policy engine from YAML policy files and middleware directory.
    pub fn from_policies(
        policies_dir: &Path,
        middlewares_dir: &Path,
        audit: AuditLogger,
    ) -> AegisResult<Self> {
        let policy = YamlPolicy::load_from_dir(policies_dir)?;
        let middleware_engine = MiddlewareEngine::load_from_dir(middlewares_dir)?;

        let http_analyzers: Vec<Box<dyn HttpAnalyzer>> = vec![
            Box::new(BuiltinHttpAnalyzer::new(policy.http.clone())),
            Box::new(SqlAnalyzer::new(policy.http.payload.clone())),
        ];

        let shell_analyzers: Vec<Box<dyn ShellAnalyzer>> = vec![
            Box::new(ShellCommandAnalyzer::new(policy.shell.clone())),
        ];

        Ok(Self {
            scope: policy.scope,
            http_analyzers,
            shell_analyzers,
            middleware_engine,
            audit,
        })
    }

    /// Evaluate an HTTP request through the full pipeline.
    pub async fn evaluate_http(&self, ctx: &RequestContext) -> Verdict {
        // 1. Scope check (always first)
        if !self.scope.is_in_scope(&ctx.host, ctx.port) {
            let verdict = Verdict::deny(
                format!("Target {}:{} is out of scope", ctx.host, ctx.port),
                "builtin:scope",
            );
            self.log_http(ctx, &verdict);
            return verdict;
        }

        // 2. Built-in HTTP analyzers (method check, payload inspection, SQL detection)
        for analyzer in &self.http_analyzers {
            if let Some(verdict) = analyzer.analyze(ctx) {
                if verdict.is_deny() {
                    self.log_http(ctx, &verdict);
                    return verdict;
                }
            }
        }

        // 3. Custom middlewares
        if let Some(verdict) = self.middleware_engine.evaluate(ctx).await {
            if verdict.is_deny() {
                self.log_http(ctx, &verdict);
                return verdict;
            }
        }

        // All passed — Allow decisions are logged by the proxy handler
        // (which enriches with secrets_applied metadata).
        Verdict::allow("policy:passed")
    }

    /// Evaluate a shell command through the pipeline.
    pub fn evaluate_shell(&self, ctx: &ShellContext) -> Verdict {
        for analyzer in &self.shell_analyzers {
            if let Some(verdict) = analyzer.analyze(ctx) {
                if verdict.is_deny() {
                    self.log_shell(ctx, &verdict);
                    return verdict;
                }
            }
        }

        let verdict = Verdict::allow("policy:passed");
        self.log_shell(ctx, &verdict);
        verdict
    }

    /// Evaluate a CONNECT tunnel request (scope check only, with audit logging).
    pub fn evaluate_connect(&self, host: &str, port: u16) -> Verdict {
        if !self.scope.is_in_scope(host, port) {
            let verdict = Verdict::deny(
                format!("Target {}:{} is out of scope", host, port),
                "builtin:scope",
            );
            self.audit.log(&AuditEntry::new(
                verdict.decision,
                verdict.reason.clone(),
                verdict.source.clone(),
                "CONNECT".to_string(),
                format!("{}:{}", host, port),
                host.to_string(),
                Layer::Proxy,
            ));
            return verdict;
        }
        Verdict::allow("policy:passed")
    }

    /// Get the target scope for external use.
    pub fn scope(&self) -> &TargetScope {
        &self.scope
    }

    fn log_http(&self, ctx: &RequestContext, verdict: &Verdict) {
        self.audit.log(&AuditEntry::with_request(
            verdict.decision,
            verdict.reason.clone(),
            verdict.source.clone(),
            ctx.method.clone(),
            ctx.url.to_string(),
            ctx.host.clone(),
            Layer::Proxy,
            ctx.headers.clone(),
            ctx.body.as_deref(),
            ctx.content_type.clone(),
        ));
    }

    fn log_shell(&self, ctx: &ShellContext, verdict: &Verdict) {
        self.audit.log(&AuditEntry::new(
            verdict.decision,
            verdict.reason.clone(),
            verdict.source.clone(),
            "SHELL".to_string(),
            ctx.command.clone(),
            "localhost".to_string(),
            Layer::Guard,
        ));
    }
}
