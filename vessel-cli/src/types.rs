use rst_common::with_errors::thiserror::{self, Error};

pub const VESSEL_DEFAULT_DIR: &str = ".vessel";
pub const VESSEL_DATA_DIR: &str = "data";
pub const VESSEL_CF_NAME: &str = "personal";

#[derive(Debug, Error)]
pub enum CliError {
    #[error("homedir error: {0}")]
    HomeDirError(String),

    #[error("database error: {0}")]
    DBError(String),

    #[error("toml error: {0}")]
    TomlError(String),

    #[error("toml error: {0}")]
    AgentError(String),
}
