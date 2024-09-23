use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::with_logging::log::debug;

use crate::commands::handler::ContextHandler;
use crate::types::CliError;

use super::AgentCommands;

const AGENT_FILE: &str = "agent.toml";

#[derive(Serialize, Deserialize)]
#[serde(crate = "self::serde")]
struct AgentConfig {
    name: String,
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

            debug!("[agent:add] name: {name} | addr: {addr}");

            let vessel_dir = ctx
                .config()
                .ok_or(CliError::HomeDirError(String::from("missing directory")))?
                .vessel_dir();

            let path_builder = format!("{}/{}", vessel_dir, AGENT_FILE);
            let agent_config_path = Path::new(path_builder.as_str());

            debug!("[agent:add] vessel_dir: {vessel_dir}");
            debug!("[agent:add] agent config path: {}", agent_config_path.to_path_buf().display());
            match agent_config_path.exists() {
                true => {
                    let mut agent_toml = read_agent_config(agent_config_path.to_path_buf().to_owned())?;
                    agent_toml.add(name, addr);

                    let _ =
                        save_agent_config(agent_config_path.to_path_buf().to_owned(), agent_toml)?;
                    Ok(())
                }
                _ => {
                    let agent_toml = AgentToml::new(name, addr);
                    save_agent_config(agent_config_path.to_path_buf().to_owned(), agent_toml)
                }
            }
        }
    }
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
