use rst_common::with_errors::thiserror::{self, Error};

#[derive(Debug, Error)]
pub enum VesselError {
    #[error("rpc error: {0}")]
    RpcError(String),
}
