use clap::{Args, Subcommand};

mod handler;

pub use handler::handle_commands as agent_handler;

#[derive(Args, Clone)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub commands: AgentCommands,
}

#[derive(Subcommand, Clone)]
#[command(subcommand_help_heading = "Agent")]
pub enum AgentCommands {
    Add(AgentAddArgs),
    List,
}

#[derive(Args, Clone)]
pub struct AgentAddArgs {
    #[arg(long, required(true))]
    name: String,

    #[arg(long, required(true))]
    addr: String,
}