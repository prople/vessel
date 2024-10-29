use clap::{ArgAction, Parser, Subcommand};

use rst_common::with_tokio::tokio;

use prople_jsonrpc_axum::rpc::RpcError;
use prople_vesseld::svc::rpc::Rpc;

#[derive(Parser)]
#[command(name = "vesseld")]
#[command(version = "1.0")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(name = "rpc")]
    #[command(about = "Running JSON-RPC server")]
    Rpc {
        #[arg(short, long, value_name = "FILE")]
        #[arg(required = true)]
        config: Option<String>,

        #[arg(long, global(true), action=ArgAction::SetTrue)]
        enable_debug: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), RpcError> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Rpc {
            config,
            enable_debug,
        } => {
            let rpc_server = Rpc::new(config.to_owned().unwrap(), *enable_debug);
            let svc = rpc_server.svc()?;
            let _ = svc.serve().await?;
        }
    }

    Ok(())
}
