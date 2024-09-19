use clap::{Args, Parser, Subcommand};
use rst_common::with_tokio::tokio;

#[derive(Parser)]
#[command(name = "prople-vessel-cli")]
#[command(version = "1.0")]
#[command(long_about = None)]
struct Cli {
    #[command(subcommand)]
    identity: IdentityCommands,
}

#[derive(Subcommand)]
#[command(subcommand_help_heading = "Identity")]
enum IdentityCommands {
    /// Used to manage Identity DID Account
    Account(AccountArgs)
}

#[derive(Args)]
struct AccountArgs {
    #[command(subcommand)]
    commands: AccountCommands 
}

#[derive(Subcommand)]
enum AccountCommands {
    #[command(name = "did-generate")]
    GenerateDID{ password: String },
    
    #[command(name = "did-build-uri")]
    BuildDIDURI(BuildDIDURIArgs),

    #[command(name = "did-resolve-uri")]
    ResolveDIDURI{ uri: String},
    
    #[command(name = "did-resolve-doc")]
    ResolveDIDDoc{ uri: String},
    
    #[command(name = "did-remove-did")]
    RemoveDID{ did: String},

    #[command(name = "did-get")]
    GetAccountDID{ did: String}
}

#[derive(Args, Debug)]
struct BuildDIDURIArgs {
    #[arg(long, short)]
    did: String,
    
    #[arg(long, short)]
    password: String,
    
    #[arg(long, short)]
    address: Option<String>,
    
    #[arg(long)]
    hl: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match &cli.identity {
        IdentityCommands::Account(args) => {
            match &args.commands {
                AccountCommands::GenerateDID { password } => {
                    println!("password: {}", password)
                }

                AccountCommands::BuildDIDURI(args) => {
                    println!("params: {:?}", args)
                }

                AccountCommands::ResolveDIDURI { uri } => {
                    println!("uri: {}", uri)
                }

                AccountCommands::ResolveDIDDoc { uri } => {
                    println!("uri: {}", uri)
                }
                
                AccountCommands::RemoveDID { did } => {
                    println!("did: {}", did)
                }
                
                AccountCommands::GetAccountDID { did } => {
                    println!("did: {}", did)
                }
            }
        }
    }
}
