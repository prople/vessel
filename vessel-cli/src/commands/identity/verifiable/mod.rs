use clap::{Args, Subcommand};

pub(crate) mod credential;

#[derive(Args, Clone)]
pub struct VerifiableArgs {
    #[command(subcommand)]
    pub commands: VerifiableCommands,
}

#[derive(Clone, Subcommand)]
pub enum VerifiableCommands {
    /// Used to manage verifiable credentials
    Credential(credential::CredentialArgs),
}
