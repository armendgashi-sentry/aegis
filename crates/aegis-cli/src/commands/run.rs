use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;

use aegis_core::audit::AuditLogger;
use aegis_core::config::AegisConfig;
use aegis_core::runtime::RuntimeConfig;
use aegis_proxy::handler::ProxyHandler;
use aegis_proxy::proxy::AegisProxy;
use aegis_proxy::rate_limiter::ProxyRateLimiter;
use aegis_proxy::tls::CertAuthority;
use aegis_sandbox::config::ResolvedSandboxPolicy;
use aegis_sandbox::platform::SandboxBackend;
use aegis_sandbox::snapshot::{self, SnapshotBackend, SnapshotInfo};

#[derive(Args)]
pub struct RunArgs {
    /// Agent to wrap: "claude", "codex", or a custom command
    pub agent: Option<String>,

    /// Arguments to pass to the agent (after --)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub agent_args: Vec<String>,

    /// Only start the proxy (no guard, no agent)
    #[arg(long)]
    pub proxy_only: bool,

    /// Only start the guard (no proxy, no agent)
    #[arg(long)]
    pub guard_only: bool,

    /// Disable HTTPS MITM interception (passthrough mode)
    #[arg(long)]
    pub no_mitm: bool,

    /// Use TUI dashboard instead of web UI
    #[arg(long)]
    pub tui: bool,

    /// Don't start the web UI server
    #[arg(long)]
    pub no_web: bool,

    /// Policy preset: conservative, moderate, aggressive, ctf
    #[arg(long)]
    pub preset: Option<String>,

    /// Path to secrets file for API key injection
    #[arg(long)]
    pub secrets: Option<PathBuf>,

    /// Run the agent in a kernel-isolated sandbox
    #[arg(long)]
    pub sandbox: bool,

    /// Path to sandbox policy YAML (default: policies/sandbox.yaml)
    #[arg(long)]
    pub sandbox_policy: Option<PathBuf>,

    /// Take a filesystem snapshot before the agent runs (enables rollback)
    #[arg(long)]
    pub snapshot: bool,

    /// Snapshot method: "auto", "git" (default: auto)
    #[arg(long, default_value = "auto")]
    pub snapshot_method: String,

    /// Config file path
    #[arg(short, long, default_value = "aegis.toml")]
    pub config: PathBuf,
}

pub async fn execute(args: RunArgs) -> anyhow::Result<()> {
    let config = AegisConfig::load(&args.config)?;

    // If a preset is specified, copy it to the policies dir before loading
    if let Some(ref preset) = args.preset {
        let preset_path = PathBuf::from(format!("configs/presets/{preset}.yaml"));
        let policies_dir = PathBuf::from(&config.policies.dir);
        if preset_path.exists() {
            std::fs::create_dir_all(&policies_dir)?;
            let dest = policies_dir.join("default.yaml");
            std::fs::copy(&preset_path, &dest)?;
            tracing::info!("Applied preset: {}", preset);
        } else {
            tracing::warn!("Preset not found: {}", preset_path.display());
        }
    }

    let policies_dir = PathBuf::from(&config.policies.dir);
    let middlewares_dir = PathBuf::from(&config.policies.middlewares_dir);

    // Per-session audit log: logs/aegis-YYYY-MM-DD_HH-MM-SS.jsonl
    aegis_core::session::ensure_log_dir()?;
    let audit_path = aegis_core::session::audit_log_path();
    tracing::info!("Session: {}", aegis_core::session::session_id());
    tracing::info!("Audit log: {}", audit_path.display());
    let audit = AuditLogger::new(Some(audit_path.to_string_lossy().to_string()));

    // Create hot-reloadable runtime config
    let runtime_config = Arc::new(RuntimeConfig::new(
        policies_dir.clone(),
        middlewares_dir.clone(),
        audit.clone(),
        args.preset.clone(),
    )?);

    // Load secrets config
    let secrets_path = args
        .secrets
        .clone()
        .or_else(|| config.secrets_file.as_ref().map(|s| AegisConfig::expand_path(s)));

    if let Some(ref path) = secrets_path {
        if path.exists() {
            match aegis_core::secrets::SecretsConfig::load(path) {
                Ok(s) => {
                    tracing::info!(
                        "Loaded {} secret rules, stripping {} env vars",
                        s.secrets.len(),
                        s.strip_env.len()
                    );
                    runtime_config.set_secrets(s);
                    runtime_config.set_secrets_path(path.clone());
                }
                Err(e) => {
                    tracing::warn!("Failed to load secrets: {}", e);
                }
            }
        } else {
            tracing::debug!("Secrets file not found: {}", path.display());
        }
    }

    // Keep a reference to secrets for strip_env during agent spawn
    let secrets = runtime_config.secrets();

    let mut tasks = Vec::new();

    // Initialize CA for MITM
    let ca_cert_path = AegisConfig::expand_path(&config.proxy.ca_cert);
    let ca_key_path = AegisConfig::expand_path(&config.proxy.ca_key);
    let mitm_enabled = !args.no_mitm && !args.guard_only;

    let ca = if mitm_enabled {
        match CertAuthority::load_or_generate(
            &ca_cert_path,
            &ca_key_path,
            config.proxy.auto_generate_ca,
        ) {
            Ok(ca) => {
                tracing::info!("CA certificate loaded from {}", ca_cert_path.display());
                Some(ca)
            }
            Err(e) => {
                tracing::warn!("Failed to load CA: {}. MITM disabled.", e);
                None
            }
        }
    } else {
        None
    };

    // Start proxy
    let rate_limiter_handle = if !args.guard_only {
        let proxy_addr: SocketAddr = config.proxy.listen.parse()?;
        let rl = runtime_config.rate_limit();
        tracing::info!("Rate limit: {} rps, burst {}, per_target={}", rl.requests_per_second, rl.burst, rl.per_target);
        let rate_limiter = ProxyRateLimiter::new(rl.requests_per_second, rl.burst, rl.per_target);

        // Build bypass list: Aegis's own services must not be policy-checked
        let mut bypass_addrs = Vec::new();
        if !args.proxy_only {
            bypass_addrs.push(config.guard.listen.clone());
        }
        if !args.no_web {
            bypass_addrs.push(config.web.listen.clone());
        }

        let handler = ProxyHandler::new(runtime_config.clone(), rate_limiter, audit.clone())
            .with_bypass(bypass_addrs);
        let rl_handle = handler.rate_limiter_handle();
        let handler = Arc::new(handler);
        let mut proxy = AegisProxy::new(handler, proxy_addr);

        if let Some(ca) = ca {
            proxy = proxy.with_ca(ca);
        }

        tasks.push(tokio::spawn(async move {
            if let Err(e) = proxy.run().await {
                tracing::error!("Proxy error: {}", e);
            }
        }));
        Some(rl_handle)
    } else {
        None
    };

    // Start guard
    if !args.proxy_only {
        let guard_addr: SocketAddr = config.guard.listen.parse()?;
        let guard_config = runtime_config.clone();

        tasks.push(tokio::spawn(async move {
            if let Err(e) =
                aegis_guard::server::start_guard_server(guard_addr, guard_config).await
            {
                tracing::error!("Guard error: {}", e);
            }
        }));
    }

    // Start web API (unless --no-web)
    let start_web = !args.no_web;
    if start_web {
        let web_addr: SocketAddr = config.web.listen.parse()?;
        let web_audit = audit.clone();
        let web_config = runtime_config.clone();
        let web_rl = rate_limiter_handle.clone();
        let static_dir = Some(PathBuf::from(&config.web.static_dir));
        tasks.push(tokio::spawn(async move {
            if let Err(e) =
                aegis_web::server::start_web_server(web_addr, web_audit, web_config, web_rl, static_dir).await
            {
                tracing::error!("Web API error: {}", e);
            }
        }));
    }

    // TUI mode: cannot wrap an agent (TUI needs the terminal)
    if args.tui && args.agent.is_some() {
        anyhow::bail!("Cannot use --tui with an agent. The TUI needs the terminal. Use the web UI instead.");
    }

    // Initialize sandbox if requested
    let sandbox = if args.sandbox {
        let sandbox_policy = {
            let policy_path = args.sandbox_policy.clone().unwrap_or_else(|| {
                PathBuf::from(&config.policies.dir).join("sandbox.yaml")
            });

            if policy_path.exists() {
                match aegis_sandbox::SandboxPolicy::load(&policy_path) {
                    Ok(p) => {
                        tracing::info!("Loaded sandbox policy from {}", policy_path.display());
                        p
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load sandbox policy: {}. Using defaults.", e);
                        aegis_sandbox::SandboxPolicy::default()
                    }
                }
            } else {
                tracing::info!("No sandbox policy file found, using defaults");
                aegis_sandbox::SandboxPolicy::default()
            }
        };

        let cwd = std::env::current_dir()?;
        let mut resolved = sandbox_policy.resolve_paths(&cwd);

        // Auto-add proxy and guard to the network allow list
        resolved.allow_connect.push(config.proxy.listen.clone());
        resolved.allow_connect.push(config.guard.listen.clone());
        if !args.no_web {
            resolved.allow_connect.push(config.web.listen.clone());
        }

        let backend = aegis_sandbox::detect_backend();
        tracing::info!("Sandbox: {}", backend.describe());

        if !backend.is_available() {
            tracing::warn!("Sandbox backend is not available — agent will run without isolation");
            None
        } else {
            Some((backend, resolved))
        }
    } else {
        None
    };

    // If an agent is specified, spawn it as a child process
    if let Some(ref agent) = args.agent {
        // Create snapshot before agent runs (if requested)
        let snapshot_state: Option<(Box<dyn SnapshotBackend>, SnapshotInfo)> = if args.snapshot {
            let cwd = std::env::current_dir()?;
            let backend = snapshot::detect_backend();

            if !backend.is_available(&cwd) {
                tracing::warn!("Snapshot backend not available (no git repo?) — skipping snapshot");
                None
            } else {
                match backend.create(&cwd) {
                    Ok(info) => {
                        tracing::info!("Snapshot created: {} ({})", info.id, info.method);
                        eprintln!("  Snapshot: {} (method: {})", info.id, info.method);
                        Some((backend, info))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create snapshot: {} — continuing without snapshot", e);
                        None
                    }
                }
            }
        } else {
            None
        };

        let proxy_addr = config.proxy.listen.clone();
        let guard_addr = config.guard.listen.clone();
        let agent = agent.clone();
        let agent_args = args.agent_args.clone();
        let ca_cert = ca_cert_path.to_string_lossy().to_string();

        // Give servers a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let strip_env: Vec<String> = secrets
            .as_ref()
            .map(|s| s.strip_env.clone())
            .unwrap_or_default();

        let agent_task = tokio::spawn(async move {
            if let Err(e) =
                spawn_agent(&agent, &agent_args, &proxy_addr, &guard_addr, &ca_cert, &strip_env, sandbox).await
            {
                tracing::error!("Agent error: {}", e);
            }
        });

        // Wait for the agent to finish, then shut down
        let _ = agent_task.await;
        tracing::info!("Agent exited. Shutting down Aegis.");

        // Post-agent snapshot handling
        if let Some((backend, snap_info)) = snapshot_state {
            handle_post_agent_snapshot(&*backend, &snap_info)?;
        }

        return Ok(());
    }

    // TUI dashboard mode
    if args.tui {
        let rx = audit.subscribe();

        // Give servers a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Run TUI (blocks until user quits)
        aegis_tui::run_live(rx, Some(runtime_config.clone())).await?;
        tracing::info!("TUI closed. Shutting down Aegis.");
        return Ok(());
    }

    let mitm_str = if mitm_enabled { " (MITM)" } else { "" };
    let sandbox_str = if args.sandbox { "ENABLED" } else { "off" };
    let session = aegis_core::session::session_id();
    eprintln!();
    eprintln!("  ╔═══════════════════════════════════════════════════╗");
    eprintln!("  ║               AEGIS IS RUNNING                   ║");
    eprintln!("  ╠═══════════════════════════════════════════════════╣");
    eprintln!("  ║  Session:  {:<38} ║", session);
    if !args.guard_only {
        eprintln!("  ║  Proxy:    http://{:<21}{:<8}║", config.proxy.listen, mitm_str);
    }
    if !args.proxy_only {
        eprintln!("  ║  Guard:    http://{:<29} ║", config.guard.listen);
    }
    if start_web {
        eprintln!("  ║  Web UI:   http://{:<29} ║", config.web.listen);
    }
    eprintln!("  ║  Sandbox:  {:<38} ║", sandbox_str);
    eprintln!("  ╠═══════════════════════════════════════════════════╣");
    eprintln!("  ║  Logs:     logs/aegis-{}.* {:<8}║", session, "");
    eprintln!("  ║  Press Ctrl+C to stop                             ║");
    eprintln!("  ╚═══════════════════════════════════════════════════╝");
    eprintln!();

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down Aegis.");
    Ok(())
}

async fn spawn_agent(
    agent: &str,
    args: &[String],
    proxy_addr: &str,
    guard_addr: &str,
    ca_cert_path: &str,
    strip_env: &[String],
    sandbox: Option<(Box<dyn SandboxBackend>, ResolvedSandboxPolicy)>,
) -> anyhow::Result<()> {
    let cmd = match agent {
        "claude" => "claude".to_string(),
        "codex" => "codex".to_string(),
        other => other.to_string(),
    };

    // Auto-configure hooks for known agents
    if agent == "claude" {
        setup_claude_hooks(guard_addr)?;
    } else if agent == "codex" {
        setup_codex_hooks(guard_addr)?;
    }

    let sandboxed = sandbox.is_some();
    tracing::info!(
        "Spawning agent: {} {:?}{}",
        cmd,
        args,
        if sandboxed { " [SANDBOXED]" } else { "" }
    );

    let proxy_url = format!("http://{proxy_addr}");

    // Build NO_PROXY list:
    // - For Claude/Codex: include localhost so guard hook calls don't loop through proxy,
    //   plus their backend API domains.
    // - For generic agents (sqlmap, scripts, etc.): NO localhost bypass — all traffic
    //   must flow through the proxy, even to localhost targets.
    let no_proxy = match agent {
        "claude" => "127.0.0.1,localhost,::1,api.anthropic.com,console.anthropic.com,sentry.io,statsig.anthropic.com".to_string(),
        "codex" => "127.0.0.1,localhost,::1,api.openai.com,sentry.io".to_string(),
        _ => String::new(),
    };

    // Build the command — sandboxed or plain
    let args_vec: Vec<String> = args.to_vec();
    let mut cmd_builder = if let Some((ref backend, ref policy)) = sandbox {
        backend.sandboxed_command(&cmd, &args_vec, policy)?
    } else {
        let mut c = tokio::process::Command::new(&cmd);
        c.args(args);
        c
    };

    cmd_builder
        .env("HTTP_PROXY", &proxy_url)
        .env("HTTPS_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("https_proxy", &proxy_url)
        .env("NO_PROXY", &no_proxy)
        .env("no_proxy", &no_proxy)
        .env("SSL_CERT_FILE", ca_cert_path)
        .env("NODE_EXTRA_CA_CERTS", ca_cert_path)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());

    // Strip sensitive env vars so the agent never sees API keys
    for var in strip_env {
        cmd_builder.env_remove(var);
        // Also strip case variants
        cmd_builder.env_remove(var.to_uppercase());
        cmd_builder.env_remove(var.to_lowercase());
        tracing::debug!("Stripped env var: {}", var);
    }

    let mut child = cmd_builder.spawn()?;

    let status = child.wait().await?;
    tracing::info!("Agent exited with status: {}", status);

    // Cleanup temp hook configs
    cleanup_hooks(agent);

    Ok(())
}

/// Handle snapshot review after the agent exits.
/// Shows a diff summary and prompts the user to accept or rollback changes.
fn handle_post_agent_snapshot(
    backend: &dyn SnapshotBackend,
    snapshot: &SnapshotInfo,
) -> anyhow::Result<()> {
    let diff = backend.diff(snapshot)?;

    eprintln!();
    eprintln!("  ╔═══════════════════════════════════════════════════╗");
    eprintln!("  ║            SNAPSHOT DIFF SUMMARY                  ║");
    eprintln!("  ╠═══════════════════════════════════════════════════╣");
    eprintln!("  ║  {:<48}║", diff.summary);
    if !diff.added.is_empty() {
        eprintln!("  ║  Added:                                           ║");
        for f in &diff.added {
            eprintln!("  ║    + {:<44}║", truncate_path(f, 44));
        }
    }
    if !diff.modified.is_empty() {
        eprintln!("  ║  Modified:                                        ║");
        for f in &diff.modified {
            eprintln!("  ║    ~ {:<44}║", truncate_path(f, 44));
        }
    }
    if !diff.deleted.is_empty() {
        eprintln!("  ║  Deleted:                                         ║");
        for f in &diff.deleted {
            eprintln!("  ║    - {:<44}║", truncate_path(f, 44));
        }
    }
    eprintln!("  ╚═══════════════════════════════════════════════════╝");
    eprintln!();

    // Check if we have a TTY for interactive prompting
    let is_tty = atty::is(atty::Stream::Stdin);

    if !is_tty {
        // Non-interactive mode: auto-commit
        eprintln!("  Non-interactive mode: auto-accepting changes.");
        backend.commit(snapshot, Some("aegis: agent changes (auto-accepted)"))?;
        tracing::info!("Snapshot auto-committed (non-interactive)");
        return Ok(());
    }

    // No changes detected — nothing to do
    if diff.added.is_empty() && diff.modified.is_empty() && diff.deleted.is_empty() {
        eprintln!("  No changes detected. Nothing to commit or rollback.");
        // Still switch back to the original branch
        backend.commit(snapshot, None)?;
        return Ok(());
    }

    // Interactive prompt loop
    loop {
        eprint!("  Accept changes? [y]es / [n]o (rollback) / [d]iff: ");
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().lock().read_line(&mut input)?;
        let choice = input.trim().to_lowercase();

        match choice.as_str() {
            "y" | "yes" => {
                backend.commit(snapshot, Some("aegis: agent changes accepted"))?;
                eprintln!("  Changes accepted and committed.");
                tracing::info!("Snapshot committed: {}", snapshot.id);
                break;
            }
            "n" | "no" => {
                backend.rollback(snapshot)?;
                eprintln!("  Changes rolled back to pre-agent state.");
                tracing::info!("Snapshot rolled back: {}", snapshot.id);
                break;
            }
            "d" | "diff" => {
                // Show full diff using git diff
                let root = std::path::Path::new(&snapshot.root);
                let output = std::process::Command::new("git")
                    .args(["diff", "HEAD"])
                    .current_dir(root)
                    .output();

                match output {
                    Ok(out) => {
                        let diff_text = String::from_utf8_lossy(&out.stdout);
                        eprintln!("{}", diff_text);
                    }
                    Err(e) => {
                        eprintln!("  Failed to show diff: {}", e);
                    }
                }
                // Loop again to ask y/n
            }
            _ => {
                eprintln!("  Please enter y, n, or d.");
            }
        }
    }

    Ok(())
}

/// Truncate a path string to fit within a fixed column width.
fn truncate_path(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("...{}", &s[s.len() - (max - 3)..])
    }
}

fn setup_claude_hooks(guard_addr: &str) -> anyhow::Result<()> {
    let guard_url = format!("http://{guard_addr}/hook");

    // Use a command hook with curl instead of an HTTP hook.
    // Claude Code inherits HTTP_PROXY which causes HTTP hooks to route through
    // the proxy, and Node.js's proxy handling may not work correctly for local
    // connections. A command hook with curl --noproxy bypasses this entirely.
    let curl_cmd = format!(
        "curl -sS --noproxy '*' --max-time 5 -X POST {} -H 'Content-Type: application/json' -d @-",
        guard_url
    );

    let hook_config = serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "Bash",
                "hooks": [{
                    "type": "command",
                    "command": curl_cmd
                }]
            }]
        }
    });

    // Claude Code requires a git repository to discover project-local settings.
    // Ensure one exists so .claude/settings.local.json is found.
    ensure_git_repo()?;

    let settings_dir = PathBuf::from(".claude");
    std::fs::create_dir_all(&settings_dir)?;

    let settings_path = settings_dir.join("settings.local.json");
    std::fs::write(&settings_path, serde_json::to_string_pretty(&hook_config)?)?;
    tracing::info!("Claude Code hooks -> {}", settings_path.display());
    Ok(())
}

/// Ensure a git repository exists in the current directory.
/// Claude Code uses the git root to discover project-local settings
/// (.claude/settings.local.json). Without a git repo, hooks won't be loaded.
fn ensure_git_repo() -> anyhow::Result<()> {
    let git_dir = PathBuf::from(".git");
    if git_dir.exists() {
        return Ok(());
    }

    tracing::info!("Initializing git repo (required for Claude Code project settings)");
    let output = std::process::Command::new("git")
        .args(["init"])
        .output()?;

    if !output.status.success() {
        tracing::warn!(
            "git init failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Non-fatal: try to continue anyway
        return Ok(());
    }

    // Add .gitignore for aegis artifacts if it doesn't exist
    let gitignore = PathBuf::from(".gitignore");
    if !gitignore.exists() {
        std::fs::write(
            &gitignore,
            "# Aegis artifacts\nlogs/\n.claude/settings.local.json\n",
        )?;
    }

    Ok(())
}

fn setup_codex_hooks(guard_addr: &str) -> anyhow::Result<()> {
    let guard_url = format!("http://{guard_addr}/hook");

    let hook_config = serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": ".*",
                "hooks": [{
                    "type": "http",
                    "url": guard_url,
                    "timeout": 5
                }]
            }]
        }
    });

    let hooks_path = PathBuf::from(".aegis-hooks.json");
    std::fs::write(&hooks_path, serde_json::to_string_pretty(&hook_config)?)?;
    tracing::info!("Codex CLI hooks -> {}", hooks_path.display());
    Ok(())
}

fn cleanup_hooks(agent: &str) {
    match agent {
        "claude" => {
            let path = PathBuf::from(".claude/settings.local.json");
            if path.exists() {
                let _ = std::fs::remove_file(&path);
                tracing::debug!("Cleaned up {}", path.display());
            }
        }
        "codex" => {
            let path = PathBuf::from(".aegis-hooks.json");
            if path.exists() {
                let _ = std::fs::remove_file(&path);
                tracing::debug!("Cleaned up {}", path.display());
            }
        }
        _ => {}
    }
}
