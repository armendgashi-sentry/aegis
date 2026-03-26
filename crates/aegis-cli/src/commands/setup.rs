use std::path::PathBuf;

use clap::Args;

use aegis_core::config::AegisConfig;

#[derive(Args)]
pub struct SetupArgs {
    /// Agent to configure: "claude-code" or "codex"
    pub agent: String,

    /// Config file path
    #[arg(short, long, default_value = "aegis.toml")]
    pub config: PathBuf,
}

pub fn execute(args: SetupArgs) -> anyhow::Result<()> {
    let config = AegisConfig::load(&args.config)?;

    match args.agent.as_str() {
        "claude-code" | "claude" => setup_claude_code(&config)?,
        "codex" => setup_codex(&config)?,
        other => {
            eprintln!("Unknown agent: {}. Supported: claude-code, codex", other);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn setup_claude_code(config: &AegisConfig) -> anyhow::Result<()> {
    let guard_url = format!("http://{}/hook", config.guard.listen);

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
    let git_dir = PathBuf::from(".git");
    if !git_dir.exists() {
        eprintln!("Initializing git repo (required for Claude Code project settings)...");
        let _ = std::process::Command::new("git").args(["init"]).output();
    }

    // Write to project-local settings (gitignored)
    let settings_dir = PathBuf::from(".claude");
    std::fs::create_dir_all(&settings_dir)?;

    let settings_path = settings_dir.join("settings.local.json");
    let settings_str = serde_json::to_string_pretty(&hook_config)?;
    std::fs::write(&settings_path, &settings_str)?;

    eprintln!("Claude Code hooks configured in {}", settings_path.display());
    eprintln!("Hook endpoint: {}", guard_url);
    Ok(())
}

fn setup_codex(config: &AegisConfig) -> anyhow::Result<()> {
    let guard_url = format!("http://{}/hook", config.guard.listen);

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

    // Write hooks.json in project root
    let hooks_path = PathBuf::from("hooks.json");
    let hooks_str = serde_json::to_string_pretty(&hook_config)?;
    std::fs::write(&hooks_path, &hooks_str)?;

    eprintln!("Codex CLI hooks configured in {}", hooks_path.display());
    eprintln!("Hook endpoint: {}", guard_url);
    Ok(())
}
