use rst_common::with_errors::thiserror::{self, Error};

#[derive(Error, PartialEq, Debug)]
pub enum DbError {
    #[error("bucket error: {0}")]
    BucketError(String),

    #[error("instruction error: {0}")]
    #[allow(dead_code)]
    InstructionError(String),
}