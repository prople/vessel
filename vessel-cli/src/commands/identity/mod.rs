use clap::Subcommand;

mod account;

pub use account::handler::handle_commands as account_handler;
pub use account::{AccountArgs, AccountCommands};

#[derive(Subcommand)]
#[command(subcommand_help_heading = "Identity")]
pub enum IdentityCommands {
    /// Used to manage Identity DID Account
    Account(AccountArgs)
}