use rst_common::with_errors::thiserror::{self, Error};

#[derive(Debug, Error, Clone)]
pub enum ProofError {
    #[error("build proof error: {0}")]
    BuildError(String),
}
