use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tailstate::{app, config::Config, storage::Store, tailscale::TailscaleClient};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "tailstate", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the monitoring service.
    Run {
        #[arg(long, default_value = "/config/tailstate.yaml")]
        config: PathBuf,
    },
    /// Validate configuration, storage, and Tailscale API access.
    Check {
        #[arg(long, default_value = "/config/tailstate.yaml")]
        config: PathBuf,
    },
    /// Print version information.
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tailstate=info,tower_http=info".into()),
        )
        .with_target(false)
        .init();

    match Cli::parse().command {
        Command::Version => println!("tailstate {}", env!("CARGO_PKG_VERSION")),
        Command::Run { config } => app::run(Config::load(&config)?).await?,
        Command::Check { config } => {
            let config = Config::load(&config)?;
            let _store = Store::open(&config.storage.path)?;
            if config.tailscale.polling_enabled {
                TailscaleClient::new(&config.tailscale)?.check().await?;
            }
            println!("configuration, storage, and enabled sources are valid");
        }
    }
    Ok(())
}
