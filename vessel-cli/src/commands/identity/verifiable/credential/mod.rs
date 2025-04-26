use clap::{Args, Subcommand};

pub(crate) mod handler;

#[derive(Args, Clone)]
pub struct CredentialArgs {
    #[command(subcommand)]
    pub commands: CredentialCommands,
}

#[derive(Clone, Subcommand)]
pub enum CredentialCommands {
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

    /// credential is a JSON string that contains the credential data
    #[arg(long, short, required = true)]
    pub credential: String,
}
