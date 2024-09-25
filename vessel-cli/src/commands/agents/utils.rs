use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use rst_common::with_logging::log::debug;

use crate::commands::handler::ContextHandler;
use crate::types::CliError;

use super::types::*;

pub(super) fn create_agent_session(ctx: &ContextHandler, name: String) -> Result<(), CliError> {
    let vessel_dir = ctx
        .config()
        .ok_or(CliError::HomeDirError(String::from("missing directory")))?
        .vessel_dir();
    
    debug!("[agent:create_agent_session] vessel_dir: {vessel_dir}");
    
    let path_builder = format!("{}/{}", vessel_dir, AGENT_SESSION);
    let path_str = path_builder.as_str();
    
    let mut agent_file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(Path::new(path_str).to_path_buf())
        .map_err(|err| CliError::AgentError(err.to_string()))?;

    let _ = agent_file
        .write_all(name.as_bytes())
        .map_err(|err| CliError::AgentError(err.to_string()))?;

    Ok(())
}

pub(super) fn build_agent_config_path(ctx: &ContextHandler) -> Result<PathBuf, CliError> {
    let vessel_dir = ctx
        .config()
        .ok_or(CliError::HomeDirError(String::from("missing directory")))?
        .vessel_dir();

    debug!("[agent:build_agent_config_path] vessel_dir: {vessel_dir}");

    let path_builder = format!("{}/{}", vessel_dir, AGENT_FILE);
    let path_str = path_builder.as_str();
    let agent_config_path = Path::new(path_str);
    Ok(agent_config_path.to_path_buf())
}

pub(super) fn read_agent_config(agent_config_path: PathBuf) -> Result<AgentToml, CliError> {
    let contents = fs::read_to_string(agent_config_path)
        .map_err(|err| CliError::TomlError(err.to_string()))?;

    let agent_toml: AgentToml =
        toml::from_str(&contents).map_err(|err| CliError::TomlError(err.to_string()))?;
    Ok(agent_toml)
}

pub(super) fn save_agent_config(agent_config_path: PathBuf, confs: AgentToml) -> Result<(), CliError> {
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