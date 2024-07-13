use rst_common::with_errors::thiserror::{self, Error};

use crate::apps::types::AppError;

#[derive(Error, PartialEq, Debug)]
pub enum DbError {
    #[error("bucket error: {0}")]
    BucketError(String),

    #[error("instruction error: {0}")]
    #[allow(dead_code)]
    InstructionError(String),
}

pub enum Instruction {
    SaveCf { key: String, value: Vec<u8> },
    MergeCf { key: String, value: Vec<u8> },
    GetCf { key: String },
    MultiGetCf { keys: Vec<String> },
    RemoveCf { key: String },
}

#[derive(Debug)]
pub enum OutputOpts {
    SingleByte {
        value: Option<Vec<u8>>,
    },
    MultiBytes {
        values: Vec<Result<Option<Vec<u8>>, AppError>>,
    },
    None,
}

impl OutputOpts {
    pub fn is_none(&self) -> bool {
        match self {
            OutputOpts::None => true,
            _ => false,
        }
    }
}
