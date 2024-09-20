use clap::Parser;
use rst_common::with_tokio::tokio;

use prople_vessel_cli::commands::identity::IdentityCommands;
use prople_vessel_cli::commands::identity::account_handler;

#[derive(Parser)]
#[command(name = "prople-vessel-cli")]
#[command(version = "0.1.0")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    identity: IdentityCommands,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match &cli.identity {
        IdentityCommands::Account(args) => account_handler(args.commands.clone())
    }
}
