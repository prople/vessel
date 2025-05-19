use clap::{Args, Subcommand};

pub(crate) mod credential;
pub(crate) mod presentation;

#[derive(Args, Clone)]
pub struct VerifiableArgs {
    #[command(subcommand)]
    pub commands: VerifiableCommands,
}

#[derive(Clone, Subcommand)]
pub enum VerifiableCommands {
    /// Used to manage verifiable credentials
    Credential(credential::CredentialArgs),

    /// Used to manage verifiable presentations
    Presentation(presentation::PresentationArgs),
}
