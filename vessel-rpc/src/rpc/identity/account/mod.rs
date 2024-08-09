use rstdev_storage::engine::rocksdb::executor::Executor;

use crate::rpc::shared::types::{CommonError, RPCService};

mod repository;

pub use repository::Repository;


pub struct Account {
    executor: Executor,
    repo: Option<Repository>,
}

impl Account {
    pub fn new(executor: Executor) -> Self {
        Self { executor, repo: None }
    }
}

impl RPCService for Account {
    fn build(&mut self) -> Result<(), CommonError> {
        self.repo = Some(Repository::new(self.executor.to_owned()));
        Ok(())
    }
}