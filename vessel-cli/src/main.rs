use clap::Parser;

use rst_common::with_logging::env_logger::{Builder, Env};
use rst_common::with_logging::log::Level;
use rst_common::with_tokio::tokio;

use prople_vessel_cli::utils::homedir::setup_homedir;
use prople_vessel_cli::utils::db::setup_database;

use prople_vessel_cli::commands::handler::ContextHandler;
use prople_vessel_cli::commands::identity::account_handler;
use prople_vessel_cli::commands::identity::IdentityCommands;

use prople_vessel_cli::types::{CliError, VESSEL_DEFAULT_DIR, VESSEL_DATA_DIR, VESSEL_CF_NAME};

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
    Builder::from_env(Env::default().default_filter_or(level)).format_timestamp(None).init();

    // setup homedir
    let vessel_dir = setup_homedir(VESSEL_DEFAULT_DIR)?;

    // setup database directory
    let db_executor = setup_database(format!("{}/{}", vessel_dir, VESSEL_DATA_DIR), String::from(VESSEL_CF_NAME))?;

    // setup handler
    let mut ctx = ContextHandler::new(db_executor);
    ctx.build_config(level.to_string(), vessel_dir);

    match &cli.identity {
        IdentityCommands::Account(args) => account_handler(&ctx, args.commands.clone()),
    }

    Ok(())
}
