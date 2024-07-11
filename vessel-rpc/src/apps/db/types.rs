use crate::apps::types::AppError;

pub enum Instruction {
    SaveCf { key: String, value: Vec<u8> },
    GetCf { key: String },
    MultiGetCf { keys: Vec<String> },
    RemoveCf { key: String },
}

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