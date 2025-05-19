use clap::{Args, Subcommand};

pub(crate) mod handler;

#[derive(Args, Clone)]
pub struct PresentationArgs {
    #[command(subcommand)]
    pub commands: PresentationCommands,
}

#[derive(Clone, Subcommand)]
pub enum PresentationCommands {
    /// Generate a credential
    #[command(name = "generate")]
    Generate(GenerateArgs),
}

#[derive(Args, Debug, Clone)]
pub struct GenerateArgs {
    /// password is a password used when build your account
    #[arg(long, short, required = true)]
    pub password: String,

    /// from_did is the DID of the issuer
    #[arg(long, short, required = true)]
    pub from_did: String,

    /// credentials is a list of credential's ids to generate 
    #[arg(long, short, value_delimiter = ',', num_args = 1..)]
    pub credentials: Vec<String>,
}