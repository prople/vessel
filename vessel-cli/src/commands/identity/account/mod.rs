use clap::{Args, Subcommand};

pub(crate) mod handler;

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
    ResolveDIDDoc { did: String },

    #[command(name = "remove-did")]
    RemoveDID { did: String },

    #[command(name = "get")]
    GetAccountDID { did: String },
}

#[derive(Args, Debug, Clone)]
pub struct BuildDIDURIArgs {
    /// chose DID account used to build the URI
    #[arg(long, required = true)]
    did: String,

    /// password is a password used when build your account
    #[arg(long, short, required = true)]
    password: String,

    /// address format: https://<host>:<port>/<params> or
    /// https://<domain>/<params>
    #[arg(long, short, required = true)]
    address: String,
}
