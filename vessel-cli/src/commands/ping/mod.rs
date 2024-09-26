mod handler;

use clap::{Args, Subcommand};

pub use handler::handle_commands as ping_handler;

#[derive(Args, Clone)]
pub struct PingArgs {
    #[command(subcommand)]
    pub commands: PingCommands,
}

#[derive(Subcommand, Clone)]
#[command(subcommand_help_heading = "Ping")]
pub enum PingCommands {
    Agent,
}
