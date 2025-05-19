use clap::{Args, Subcommand};

mod account;
mod verifiable;

pub use account::handler::handle_commands as account_handler;
pub use account::{AccountArgs, AccountCommands};

pub use verifiable::credential::handler::handle_commands as credential_handler;
pub use verifiable::presentation::handler::handle_commands as presentation_handler;
pub use verifiable::{VerifiableArgs, VerifiableCommands};

#[derive(Args)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub commands: IdentityCommands,
}

#[derive(Subcommand)]
#[command(subcommand_help_heading = "Identity")]
pub enum IdentityCommands {
    /// Used to manage Identity DID Account
    Account(AccountArgs),

    /// Used to manage verifiable credentials and presentations
    Verifiable(VerifiableArgs),
}
