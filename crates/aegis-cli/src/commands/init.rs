use std::path::PathBuf;

use clap::Args;

#[derive(Args)]
pub struct InitArgs {
    /// Target domains/CIDRs (can be specified multiple times)
    #[arg(short, long)]
    pub target: Vec<String>,

    /// Allowed ports (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    pub ports: Vec<u16>,

    /// Policy preset: conservative, moderate, aggressive, ctf
    #[arg(long, default_value = "moderate")]
    pub preset: String,

    /// Output directory for config files
    #[arg(short, long, default_value = ".")]
    pub output: PathBuf,
}

pub fn execute(args: InitArgs) -> anyhow::Result<()> {
    let output = &args.output;

    // Generate aegis.toml
    let config_path = output.join("aegis.toml");
    if !config_path.exists() {
        let config = generate_config();
        std::fs::write(&config_path, config)?;
        eprintln!("Created {}", config_path.display());
    } else {
        eprintln!("Config already exists: {}", config_path.display());
    }

    // Generate policies directory
    let policies_dir = output.join("policies");
    std::fs::create_dir_all(&policies_dir)?;
    std::fs::create_dir_all(policies_dir.join("middlewares"))?;

    // Generate scope.yaml
    let scope_path = policies_dir.join("scope.yaml");
    let scope = generate_scope(&args.target, &args.ports);
    std::fs::write(&scope_path, scope)?;
    eprintln!("Created {}", scope_path.display());

    // Generate default.yaml
    let default_path = policies_dir.join("default.yaml");
    if !default_path.exists() {
        let default_policy = generate_default_policy();
        std::fs::write(&default_path, default_policy)?;
        eprintln!("Created {}", default_path.display());
    }

    // Generate example middleware
    let mw_path = policies_dir.join("middlewares").join("example-block-admin.yaml");
    if !mw_path.exists() {
        let mw = generate_example_middleware();
        std::fs::write(&mw_path, mw)?;
        eprintln!("Created {}", mw_path.display());
    }

    eprintln!();
    eprintln!("Aegis initialized. Run `aegis run` to start.");
    Ok(())
}

fn generate_config() -> String {
    r#"[proxy]
listen = "127.0.0.1:19000"
ca_cert = "~/.config/aegis/ca.pem"
ca_key = "~/.config/aegis/ca-key.pem"
auto_generate_ca = true

[guard]
listen = "127.0.0.1:19001"

[web]
listen = "127.0.0.1:19002"
static_dir = "./web/dist"

[audit]
log_file = "./aegis-audit.jsonl"
max_entries = 50000

[policies]
dir = "./policies"
middlewares_dir = "./policies/middlewares"
"#
    .to_string()
}

fn generate_scope(targets: &[String], ports: &[u16]) -> String {
    let targets_yaml: Vec<String> = targets.iter().map(|t| format!("  - \"{}\"", t)).collect();
    let ports_yaml: Vec<String> = ports.iter().map(|p| format!("  - {}", p)).collect();

    let targets_str = if targets_yaml.is_empty() {
        "  # Add targets: \"*.example.com\", \"10.0.0.0/24\"".to_string()
    } else {
        targets_yaml.join("\n")
    };

    let ports_str = if ports_yaml.is_empty() {
        "  - 80\n  - 443\n  - 8080\n  - 8443".to_string()
    } else {
        ports_yaml.join("\n")
    };

    format!(
        r#"scope:
  targets:
{targets_str}
  ports:
{ports_str}
  exclusions: []
"#
    )
}

fn generate_default_policy() -> String {
    r#"http:
  methods:
    safe: [GET, HEAD, OPTIONS, TRACE]
    inspect: [POST, PUT, PATCH]
    block: [DELETE]

  payload:
    block_sql:
      - DROP
      - DELETE
      - TRUNCATE
      - "ALTER TABLE"
      - UPDATE
    allow_sql:
      - SELECT
      - UNION
      - SHOW
      - DESCRIBE
    block_commands:
      - "rm -rf"
      - "rm -r"
      - "dd if="
      - mkfs
      - shutdown
      - reboot

  max_request_body: 10485760

shell:
  block_patterns:
    - "rm -rf"
    - "rm -r"
    - rmdir
    - "dd if="
    - mkfs
    - shred
    - "> /dev/"
    - shutdown
    - reboot
  block_sql_in_cli: true

rate_limit:
  requests_per_second: 10
  burst: 50
  per_target: true
"#
    .to_string()
}

fn generate_example_middleware() -> String {
    r#"# Example middleware: block requests to admin endpoints
# Remove or modify this file for your engagement
name: block-admin-endpoints
description: Block all requests to admin paths
trigger:
  path_matches: "/admin/*"
action: block
reason: "Admin endpoints are excluded from scope"
"#
    .to_string()
}
