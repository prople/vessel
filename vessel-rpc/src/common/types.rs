use rst_common::with_errors::thiserror::{self, Error};

#[derive(Debug, PartialEq, Error)]
pub enum CommonError {
    #[error("valdation error: {0}")]
    ValidationError(String),

    #[error("db error: {0}")]
    DBError(String),
}

pub trait ToValidate {
    fn validate(&self) -> Result<(), CommonError>;
}
