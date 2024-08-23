use rstdev_storage::engine::rocksdb::executor::Executor;

use prople_jsonrpc_client::executor::reqwest::Reqwest as ReqwestExecutor;
use prople_vessel_core::identity::verifiable::credential::types::CredentialError;

use crate::rpc::shared::types::{CommonError, RPCService};

mod repository;
mod rpc_client;

pub use repository::Repository;
pub use rpc_client::RpcClient;

pub struct Credential {
    executor: Executor,
    repo: Option<Repository>,
    rpc_client: Option<RpcClient<ReqwestExecutor<(), CredentialError>>>,
}

impl Credential {
    pub fn new(executor: Executor) -> Self {
        Self {
            executor,
            repo: None,
            rpc_client: None,
        }
    }
}

impl RPCService for Credential {
    fn build(&mut self) -> Result<(), CommonError> {
        self.repo = Some(Repository::new(self.executor.to_owned()));
        self.rpc_client = Some(RpcClient::new(ReqwestExecutor::new()));
        Ok(())
    }
}
