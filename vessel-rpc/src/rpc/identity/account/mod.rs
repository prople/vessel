use rstdev_storage::engine::rocksdb::executor::Executor as DbExecutor;

use prople_did_core::doc::types::Doc;
use prople_jsonrpc_client::executor::reqwest::Reqwest as ReqwestExecutor;
use prople_vessel_core::identity::account::types::AccountError;

use crate::rpc::shared::types::{CommonError, RPCService};

mod repository;
mod rpc_client;

pub use repository::Repository;
pub use rpc_client::RpcClient;

pub struct Account {
    db_executor: DbExecutor,
    repo: Option<Repository>,
    rpc_client: Option<RpcClient<ReqwestExecutor<Doc, AccountError>>>,
}

impl Account {
    pub fn new(db_executor: DbExecutor) -> Self {
        Self {
            db_executor,
            repo: None,
            rpc_client: None,
        }
    }
}

impl RPCService for Account {
    fn build(&mut self) -> Result<(), CommonError> {
        self.repo = Some(Repository::new(self.db_executor.to_owned()));
        self.rpc_client = Some(RpcClient::new(ReqwestExecutor::new()));
        Ok(())
    }
}
