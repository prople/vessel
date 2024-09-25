use cli_table::{print_stdout, WithTitle};

use rst_common::with_logging::log::{debug, info};

use crate::commands::handler::ContextHandler;
use crate::types::CliError;

use super::AgentCommands;

use super::types::*;
use super::utils::*;

pub fn handle_commands(ctx: &ContextHandler, commands: AgentCommands) -> Result<(), CliError> {
    debug!("agent command handler triggered...");

    match commands {
        AgentCommands::Add(args) => {
            let name = args.name;
            let addr = args.addr;

            debug!("[agent:add] triggered...");
            debug!("[agent:add] name: {name} | addr: {addr}");

            let agent_config_path = build_agent_config_path(ctx)?;
            debug!(
                "[agent:add] agent config path: {}",
                agent_config_path.display()
            );

            match agent_config_path.exists() {
                true => {
                    let mut agent_toml = read_agent_config(agent_config_path.clone())?;
                    agent_toml.add(name, addr);

                    let _ = save_agent_config(agent_config_path.clone(), agent_toml)?;
                }
                _ => {
                    let agent_toml = AgentToml::new(name, addr);
                    let _ = save_agent_config(agent_config_path, agent_toml)?;
                }
            }
        }
        AgentCommands::List => {
            debug!("[agent:list] triggered...");

            let agent_config_path = build_agent_config_path(ctx)?;
            debug!(
                "[agent:list] agent config path: {}",
                agent_config_path.display()
            );

            let agent_toml = read_agent_config(agent_config_path)?;
            let mut agent_table: Vec<AgentConfig> = Vec::new();
            agent_table.append(&mut agent_toml.agents());

            let _ = print_stdout(agent_table.with_title())
                .map_err(|err| CliError::AgentError(err.to_string()))?;
        }
        AgentCommands::Session(args) => {
            debug!("[agent:session] triggered...");
            
            let agent_config_path = build_agent_config_path(ctx)?;
            debug!(
                "[agent:session] agent config path: {}",
                agent_config_path.display()
            );
            
            let agent_toml = read_agent_config(agent_config_path)?;
            let mut selected_agent = String::from("");

            for agent in agent_toml.agents() {
                if args.name.eq(&agent.name()) {
                    selected_agent = agent.name()
                }
            }

            if selected_agent.is_empty() {
                return Err(CliError::AgentError(String::from("unknown agent name")))
            }

            let _ = create_agent_session(ctx, selected_agent.clone());
            info!("[agent:session] Agent session already been set: {}", selected_agent)
        }
    }
            
    Ok(())
}
