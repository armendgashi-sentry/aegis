use std::path::PathBuf;

use clap::Args;

use aegis_core::audit;
use aegis_core::session;

#[derive(Args)]
pub struct LogsArgs {
    /// Path to a specific audit log file. If omitted, lists available logs or opens the latest.
    pub file: Option<PathBuf>,

    /// List available log files instead of opening a viewer
    #[arg(long)]
    pub list: bool,
}

pub fn execute(args: LogsArgs) -> anyhow::Result<()> {
    if args.list {
        return list_logs();
    }

    let path = match args.file {
        Some(p) => p,
        None => find_latest_log()?,
    };

    aegis_tui::run_log_viewer(&path)
}

fn list_logs() -> anyhow::Result<()> {
    let dir = PathBuf::from(session::LOG_DIR);
    let logs = audit::find_audit_logs(&dir);

    if logs.is_empty() {
        eprintln!("No session logs found in {}", dir.display());
        return Ok(());
    }

    eprintln!("  Session logs in {}:", dir.display());
    eprintln!();
    for log in &logs {
        let size = std::fs::metadata(log).map(|m| m.len()).unwrap_or(0);
        let entries = audit::read_audit_log(log).map(|e| e.len()).unwrap_or(0);
        let name = log.file_name().unwrap_or_default().to_string_lossy();
        let size_kb = size as f64 / 1024.0;
        eprintln!("  {name:<40} {size_kb:>8.1} KB  {entries:>6} entries");
    }
    eprintln!();

    Ok(())
}

fn find_latest_log() -> anyhow::Result<PathBuf> {
    let dir = PathBuf::from(session::LOG_DIR);
    let logs = audit::find_audit_logs(&dir);

    match logs.last() {
        Some(path) => Ok(path.clone()),
        None => anyhow::bail!("No session logs found in {}", dir.display()),
    }
}
