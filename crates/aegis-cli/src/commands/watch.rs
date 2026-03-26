use std::path::PathBuf;

use clap::Args;

use aegis_core::config::AegisConfig;

#[derive(Args)]
pub struct WatchArgs {
    /// Aegis web UI address to connect to (default: from config)
    #[arg(short, long)]
    pub addr: Option<String>,

    /// Config file path
    #[arg(short, long, default_value = "aegis.toml")]
    pub config: PathBuf,
}

pub async fn execute(args: WatchArgs) -> anyhow::Result<()> {
    let addr = if let Some(ref addr) = args.addr {
        addr.clone()
    } else if args.config.exists() {
        let config = AegisConfig::load(&args.config)?;
        config.web.listen.clone()
    } else {
        "127.0.0.1:19002".to_string()
    };

    let ws_url = format!("ws://{addr}/api/live");

    eprintln!("Connecting to Aegis at {}...", ws_url);

    match aegis_tui::run_watch(&ws_url).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("Connection refused") {
                anyhow::bail!(
                    "Could not connect to Aegis at {addr}. Is `aegis run` running?"
                );
            }
            Err(e)
        }
    }
}
