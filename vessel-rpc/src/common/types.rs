use rst_common::with_errors::thiserror::{self, Error};

#[derive(Debug, PartialEq, Error)]
pub enum CommonError {
    #[error("valdation error: {0}")]
    ValidationError(String),
}

pub trait ToValidate {
    fn validate(&self) -> Result<(), CommonError>;
}