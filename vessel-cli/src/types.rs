use rst_common::with_errors::thiserror::{self, Error};

pub const VESSEL_DEFAULT_DIR: &str = ".vessel";

#[derive(Debug, Error)]
pub enum CliError {
    #[error("homedir error: {0}")]
    HomeDirError(String)
}