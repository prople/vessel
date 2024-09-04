use clap::{Parser, Subcommand};
use rst_common::with_tokio::tokio;

use vesseld::errors::VesselError;
use vesseld::svc::rpc::Rpc;

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
    },
}

#[tokio::main]
async fn main() -> Result<(), VesselError> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Rpc { config } => {
            let rpc_server = Rpc::new(config.to_owned().unwrap());
            let svc = rpc_server.svc()?;
            let _ = svc.serve().await?;
        }
    }

    Ok(())
}
