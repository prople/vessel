use clap::{Args, Subcommand};

pub mod handler;

#[derive(Args)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub commands: AccountCommands,
}

#[derive(Clone, Subcommand)]
pub enum AccountCommands {
    #[command(name = "generate")]
    GenerateDID { password: String },

    #[command(name = "build-uri")]
    BuildDIDURI(BuildDIDURIArgs),

    #[command(name = "resolve-uri")]
    ResolveDIDURI { uri: String },

    #[command(name = "resolve-doc")]
    ResolveDIDDoc { uri: String },

    #[command(name = "remove-did")]
    RemoveDID { did: String },

    #[command(name = "get")]
    GetAccountDID { did: String },
}

#[derive(Args, Debug, Clone)]
pub struct BuildDIDURIArgs {
    #[arg(long, short)]
    did: String,

    #[arg(long, short)]
    password: String,

    #[arg(long, short)]
    address: Option<String>,

    #[arg(long)]
    hl: Option<String>,
}
