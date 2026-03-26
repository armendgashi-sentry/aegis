use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;

use aegis_core::analyzer::{RequestContext, ShellContext};
use aegis_core::audit::AuditLogger;
use aegis_core::config::AegisConfig;
use aegis_core::decision::Decision;
use aegis_core::policy::PolicyEngine;

#[derive(Args)]
pub struct EvalArgs {
    /// Command or URL to evaluate.
    /// URLs (http:// or https://) are evaluated as HTTP requests.
    /// Everything else is evaluated as a shell command.
    pub input: String,

    /// Force evaluation as a shell command
    #[arg(long)]
    pub shell: bool,

    /// Force evaluation as an HTTP request
    #[arg(long)]
    pub url: bool,

    /// HTTP method (default: GET, or POST if --body is provided)
    #[arg(long, short)]
    pub method: Option<String>,

    /// Request body. Supports raw strings, JSON, form-encoded data.
    /// Use @filename to read body from a file.
    #[arg(long, short)]
    pub body: Option<String>,

    /// HTTP headers (repeatable). Format: "Name: Value"
    #[arg(long = "header", short = 'H')]
    pub headers: Vec<String>,

    /// Content-Type header. Auto-detected if not specified:
    /// JSON body -> application/json, otherwise application/x-www-form-urlencoded
    #[arg(long)]
    pub content_type: Option<String>,

    /// Config file path
    #[arg(short, long, default_value = "aegis.toml")]
    pub config: PathBuf,
}

pub async fn execute(args: EvalArgs) -> anyhow::Result<()> {
    let config = AegisConfig::load(&args.config)?;
    let policies_dir = PathBuf::from(&config.policies.dir);
    let middlewares_dir = PathBuf::from(&config.policies.middlewares_dir);

    let audit = AuditLogger::new(None);
    let engine = Arc::new(PolicyEngine::from_policies(
        &policies_dir,
        &middlewares_dir,
        audit,
    )?);

    let is_http = args.url
        || (!args.shell
            && (args.input.starts_with("http://") || args.input.starts_with("https://")));

    if is_http {
        eval_http(&engine, &args).await
    } else {
        eval_shell(&engine, &args)
    }
}

async fn eval_http(engine: &PolicyEngine, args: &EvalArgs) -> anyhow::Result<()> {
    let parsed = url::Url::parse(&args.input)?;
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let path = parsed.path().to_string();

    // Resolve body (support @filename)
    let body_string = match &args.body {
        Some(b) if b.starts_with('@') => {
            let path = &b[1..];
            Some(std::fs::read_to_string(path)?)
        }
        Some(b) => Some(b.clone()),
        None => None,
    };

    let body = body_string
        .as_ref()
        .map(|b| bytes::Bytes::from(b.clone()));

    // Determine HTTP method: explicit > inferred from body > GET
    let method = args
        .method
        .as_ref()
        .map(|m| m.to_uppercase())
        .unwrap_or_else(|| {
            if body.is_some() {
                "POST".to_string()
            } else {
                "GET".to_string()
            }
        });

    // Determine content type
    let content_type = args
        .content_type
        .clone()
        .or_else(|| {
            body_string.as_ref().map(|b| {
                // Auto-detect: if it looks like JSON, use application/json
                let trimmed = b.trim();
                if (trimmed.starts_with('{') && trimmed.ends_with('}'))
                    || (trimmed.starts_with('[') && trimmed.ends_with(']'))
                {
                    "application/json".to_string()
                } else {
                    "application/x-www-form-urlencoded".to_string()
                }
            })
        });

    // Parse headers
    let mut headers = HashMap::new();
    for h in &args.headers {
        if let Some((name, value)) = h.split_once(':') {
            headers.insert(
                name.trim().to_lowercase(),
                value.trim().to_string(),
            );
        } else {
            eprintln!("Warning: ignoring malformed header (expected \"Name: Value\"): {h}");
        }
    }

    // Add content-type to headers if present
    if let Some(ref ct) = content_type {
        headers
            .entry("content-type".to_string())
            .or_insert_with(|| ct.clone());
    }

    let ctx = RequestContext {
        method: method.clone(),
        url: parsed,
        host: host.clone(),
        port,
        path,
        headers: headers.clone(),
        body,
        content_type,
    };

    let verdict = engine.evaluate_http(&ctx).await;

    // Display result
    let header_summary = if headers.is_empty() {
        String::new()
    } else {
        let count = headers.len();
        format!(" \x1b[90m({count} header{})\x1b[0m", if count == 1 { "" } else { "s" })
    };

    let body_summary = if let Some(ref b) = body_string {
        let len = b.len();
        if len > 60 {
            format!(" \x1b[90m[body: {}... ({len}B)]\x1b[0m", &b[..57])
        } else {
            format!(" \x1b[90m[body: {b}]\x1b[0m")
        }
    } else {
        String::new()
    };

    match verdict.decision {
        Decision::Allow => {
            eprintln!(
                "\x1b[32mALLOWED\x1b[0m: {method} {}{header_summary}{body_summary} \x1b[90m({})\x1b[0m",
                args.input,
                verdict.source
            );
        }
        Decision::Deny => {
            eprintln!(
                "\x1b[31mDENIED\x1b[0m: {method} {}{header_summary}{body_summary} \x1b[90m[{}: {}]\x1b[0m",
                args.input,
                verdict.source,
                verdict.reason
            );
        }
    }

    // Return non-zero exit for denied (useful in scripts)
    if verdict.decision == Decision::Deny {
        std::process::exit(1);
    }

    Ok(())
}

fn eval_shell(engine: &PolicyEngine, args: &EvalArgs) -> anyhow::Result<()> {
    let ctx = ShellContext {
        command: args.input.clone(),
        tool_name: "eval".into(),
        cwd: None,
    };

    let verdict = engine.evaluate_shell(&ctx);

    match verdict.decision {
        Decision::Allow => {
            eprintln!("\x1b[32mALLOWED\x1b[0m: {}", args.input);
        }
        Decision::Deny => {
            eprintln!(
                "\x1b[31mDENIED\x1b[0m: {} \x1b[90m[{}: {}]\x1b[0m",
                args.input, verdict.source, verdict.reason
            );
            std::process::exit(1);
        }
    }

    Ok(())
}
