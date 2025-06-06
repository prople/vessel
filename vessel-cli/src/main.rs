use clap::{ArgAction, Parser, Subcommand};

use rst_common::with_logging::env_logger::{Builder, Env};
use rst_common::with_logging::log::Level;
use rst_common::with_tokio::tokio;

use prople_vessel_cli::utils::db::setup_database;
use prople_vessel_cli::utils::homedir::setup_homedir;

use prople_vessel_cli::commands::handler::ContextHandler;

use prople_vessel_cli::commands::agents::agent_handler;
use prople_vessel_cli::commands::agents::AgentArgs;

use prople_vessel_cli::commands::ping::ping_handler;
use prople_vessel_cli::commands::ping::PingArgs;

use prople_vessel_cli::commands::identity::VerifiableCommands;
use prople_vessel_cli::commands::identity::{
    account_handler, credential_handler, presentation_handler,
};
use prople_vessel_cli::commands::identity::{IdentityArgs, IdentityCommands};

use prople_vessel_cli::types::{CliError, VESSEL_CF_NAME, VESSEL_DATA_DIR, VESSEL_DEFAULT_DIR};

#[derive(Parser)]
#[command(name = "prople-vessel-cli")]
#[command(version = "0.2.0")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    commands: Commands,

    #[arg(long, global(true), action=ArgAction::SetTrue)]
    enable_debug: bool,

    #[arg(long, global(true))]
    agent: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    // Manage your identity and credentials
    Identity(IdentityArgs),

    // Manage your prople agent entities
    Agent(AgentArgs),

    // Ping to some of your agents
    Ping(PingArgs),
}

#[tokio::main]
async fn main() -> Result<(), CliError> {
    let cli = Cli::parse();
    let mut level = Level::Info.as_str();

    if cli.enable_debug {
        level = Level::Debug.as_str();
    }

    // setup logging configurations
    Builder::from_env(Env::default().default_filter_or(level))
        .format_timestamp(None)
        .init();

    // setup homedir
    let vessel_dir = setup_homedir(VESSEL_DEFAULT_DIR)?;

    // setup database directory
    let db_executor = setup_database(
        format!("{}/{}", vessel_dir, VESSEL_DATA_DIR),
        String::from(VESSEL_CF_NAME),
    )?;

    // setup context handler
    let mut ctx = ContextHandler::new(db_executor);
    ctx.build_config(level.to_string(), vessel_dir);
    let _ = ctx.set_agent(cli.agent)?;

    match &cli.commands {
        Commands::Identity(args) => match &args.commands {
            IdentityCommands::Account(args) => account_handler(&ctx, args.commands.clone()).await?,
            IdentityCommands::Verifiable(args) => match &args.commands {
                VerifiableCommands::Credential(args) => {
                    credential_handler(&ctx, args.commands.clone()).await?
                }
                VerifiableCommands::Presentation(args) => {
                    presentation_handler(&ctx, args.commands.clone()).await?
                }
            },
        },
        Commands::Agent(args) => agent_handler(&ctx, args.commands.clone())?,
        Commands::Ping(args) => ping_handler(&ctx, args.commands.clone()).await?,
    }

    Ok(())
}
