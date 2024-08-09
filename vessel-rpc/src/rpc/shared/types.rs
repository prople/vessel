use rst_common::with_errors::thiserror::{self, Error};

#[derive(Debug, Error, PartialEq)]
pub enum CommonError {
    #[error("dberror: {0}")]
    DbError(String),

    #[error("valdation error: {0}")]
    ValidationError(String),
}

pub trait ToValidate {
    fn validate(&self) -> Result<(), CommonError>;
}

pub trait RPCService {
    fn build(&mut self) -> Result<(), CommonError>;
}
