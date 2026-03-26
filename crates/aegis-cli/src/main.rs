mod commands;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "aegis",
    about = "HTTP proxy guardrail for AI agent pentesting",
    version,
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start Aegis proxy, guard, and optionally wrap an agent
    Run(commands::run::RunArgs),

    /// Initialize Aegis config and policies for a new engagement
    Init(commands::init::InitArgs),

    /// Evaluate a command or URL against the current policy
    Eval(commands::eval::EvalArgs),

    /// Configure agent hooks (claude-code, codex)
    Setup(commands::setup::SetupArgs),

    /// View audit logs in the TUI viewer
    Logs(commands::logs::LogsArgs),

    /// Connect to a running Aegis instance and show live TUI dashboard
    Watch(commands::watch::WatchArgs),
}

/// Check if logs should go to a file instead of stderr.
/// This is needed when --tui is active or when wrapping an agent,
/// because stderr output would corrupt the agent's or our own TUI.
fn needs_file_logging() -> bool {
    let args: Vec<String> = std::env::args().collect();

    // --tui flag or watch command (both use the terminal)
    if args.iter().any(|a| a == "--tui" || a == "watch") {
        return true;
    }

    // `aegis run <agent>` where agent is the first positional arg after "run"
    // If there's a positional arg after "run" that isn't a flag, we're wrapping an agent
    if let Some(run_pos) = args.iter().position(|a| a == "run") {
        for arg in &args[run_pos + 1..] {
            if arg == "--" {
                // `aegis run -- cmd`: wrapping a custom command
                return true;
            }
            if arg.starts_with('-') {
                continue; // skip flags
            }
            // First positional arg after "run" = agent name
            return true;
        }
    }

    false
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use aegis_core::session;

    let file_logging = needs_file_logging();
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if file_logging {
        // Write logs to a session-specific file so they don't corrupt the agent's or our own TUI
        session::ensure_log_dir()?;
        let log_path = session::tracing_log_path();
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(log_file)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => commands::run::execute(args).await?,
        Commands::Init(args) => commands::init::execute(args)?,
        Commands::Eval(args) => commands::eval::execute(args).await?,
        Commands::Setup(args) => commands::setup::execute(args)?,
        Commands::Logs(args) => commands::logs::execute(args)?,
        Commands::Watch(args) => commands::watch::execute(args).await?,
    }

    Ok(())
}
