use rstdev_storage::engine::rocksdb::executor::Executor;

use prople_jsonrpc_client::executor::reqwest::Reqwest as ReqwestExecutor;
use prople_vessel_core::identity::verifiable::presentation::types::PresentationError;
use crate::rpc::shared::types::{CommonError, RPCService};

mod repository;
mod rpc_client;

pub use repository::Repository;
pub use rpc_client::RpcClient;

pub struct Presentation {
    executor: Executor,
    repo: Option<Repository>,
    rpc_client: Option<RpcClient<ReqwestExecutor<(), PresentationError>>>,
}

impl Presentation {
    pub fn new(executor: Executor) -> Self {
        Self {
            executor,
            repo: None,
            rpc_client: None,
        }
    }
}

impl RPCService for Presentation {
    fn build(&mut self) -> Result<(), CommonError> {
        self.repo = Some(Repository::new(self.executor.to_owned()));
        self.rpc_client = Some(RpcClient::new(ReqwestExecutor::new()));
        Ok(())
    }
}
