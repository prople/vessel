use clap::Parser;

use rst_common::with_logging::env_logger::{Builder, Env};
use rst_common::with_logging::log::Level;
use rst_common::with_tokio::tokio;

use prople_vessel_cli::commands::identity::account_handler;
use prople_vessel_cli::commands::identity::IdentityCommands;
use prople_vessel_cli::utils::homedir::setup_homedir;
use prople_vessel_cli::types::{CliError, VESSEL_DEFAULT_DIR};

#[derive(Parser)]
#[command(name = "prople-vessel-cli")]
#[command(version = "0.1.0")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    identity: IdentityCommands,

    #[arg(long, global(true))]
    enable_debug: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    let mut level = Level::Info.as_str();

    if let Some(val) = &cli.enable_debug {
        if val.to_owned() {
            level = Level::Debug.as_str();
        }
    }

    // setup logging configurations
    Builder::from_env(Env::default().default_filter_or(level)).init();

    // setup homedir
    let _ = setup_homedir(VESSEL_DEFAULT_DIR)?;

    match &cli.identity {
        IdentityCommands::Account(args) => account_handler(args.commands.clone()),
    }

    Ok(())
}
