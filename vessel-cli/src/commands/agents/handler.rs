use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use cli_table::{print_stdout, Table, WithTitle};

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::with_logging::log::debug;

use crate::commands::handler::ContextHandler;
use crate::types::CliError;

use super::AgentCommands;

const AGENT_FILE: &str = "agent.toml";

#[derive(Serialize, Deserialize, Table)]
#[serde(crate = "self::serde")]
struct AgentConfig {
    #[table(title = "Name")]
    name: String,
    #[table(title = "Address")]
    addr: String,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "self::serde")]
struct AgentToml {
    agents: Vec<AgentConfig>,
}

impl AgentToml {
    fn new(name: String, addr: String) -> Self {
        let agent_config = AgentConfig { name, addr };
        let mut agents: Vec<AgentConfig> = Vec::new();
        agents.push(agent_config);

        Self { agents }
    }

    fn add(&mut self, name: String, addr: String) {
        self.agents.push(AgentConfig { name, addr });
    }
}

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
                    Ok(())
                }
                _ => {
                    let agent_toml = AgentToml::new(name, addr);
                    save_agent_config(agent_config_path, agent_toml)
                }
            }
        }
        AgentCommands::List => {
            debug!("[agent:list] triggered...");

            let agent_config_path = build_agent_config_path(ctx)?;
            debug!(
                "[agent:add] agent config path: {}",
                agent_config_path.display()
            );

            let mut agent_toml = read_agent_config(agent_config_path)?;
            let mut agent_table: Vec<AgentConfig> = Vec::new();
            agent_table.append(&mut agent_toml.agents);

            let _ = print_stdout(agent_table.with_title())
                .map_err(|err| CliError::TomlError(err.to_string()))?;

            Ok(())
        }
    }
}

fn build_agent_config_path(ctx: &ContextHandler) -> Result<PathBuf, CliError> {
    let vessel_dir = ctx
        .config()
        .ok_or(CliError::HomeDirError(String::from("missing directory")))?
        .vessel_dir();

    debug!("[agent:add] vessel_dir: {vessel_dir}");

    let path_builder = format!("{}/{}", vessel_dir, AGENT_FILE);
    let path_str = path_builder.as_str();
    let agent_config_path = Path::new(path_str);
    Ok(agent_config_path.to_path_buf())
}

fn read_agent_config(agent_config_path: PathBuf) -> Result<AgentToml, CliError> {
    let contents = fs::read_to_string(agent_config_path)
        .map_err(|err| CliError::TomlError(err.to_string()))?;

    let agent_toml: AgentToml =
        toml::from_str(&contents).map_err(|err| CliError::TomlError(err.to_string()))?;
    Ok(agent_toml)
}

fn save_agent_config(agent_config_path: PathBuf, confs: AgentToml) -> Result<(), CliError> {
    let agent_toml = toml::to_string(&confs).map_err(|err| CliError::TomlError(err.to_string()))?;
    let mut agent_file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(agent_config_path)
        .map_err(|err| CliError::TomlError(err.to_string()))?;

    let _ = agent_file
        .write_all(agent_toml.as_bytes())
        .map_err(|err| CliError::TomlError(err.to_string()))?;

    Ok(())
}
