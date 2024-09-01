use prople_jsonrpc_core::types::RpcRoute;
use rst_common::with_errors::thiserror::{self, Error};

#[derive(Debug, Error, PartialEq)]
pub enum CommonError {
    #[error("dberror: {0}")]
    DbError(String),

    #[error("valdation error: {0}")]
    ValidationError(String),

    #[error("json error: {0}")]
    JSONError(String),

    #[error("internal error: {0}")]
    InternalError(String),

    #[error("method error: {0}")]
    MethodError(String),
}

pub trait ToValidate {
    fn validate(&self) -> Result<(), CommonError>;
}

pub trait RPCService {
    fn build(&mut self) -> Result<(), CommonError>;
    fn setup_rpc(&mut self) -> Result<(), CommonError>;
    fn routes(&self) -> Vec<RpcRoute>;
}
