use rstdev_storage::engine::rocksdb::executor::Executor;

use crate::rpc::shared::types::{CommonError, RPCService};

pub mod repository;

pub struct Credential {
    executor: Executor,
    repo: Option<repository::Repository>,
}

impl Credential {
    pub fn new(executor: Executor) -> Self {
        Self {
            executor,
            repo: None,
        }
    }
}

impl RPCService for Credential {
    fn build(&mut self) -> Result<(), CommonError> {
        self.repo = Some(repository::Repository::new(self.executor.to_owned()));
        Ok(())
    }
}
