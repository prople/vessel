use rstdev_storage::engine::rocksdb::executor::Executor;

use crate::rpc::shared::types::{CommonError, RPCService};

pub mod repository;

pub struct Presentation {
    executor: Executor,
    repo: Option<repository::Repository>,
}

impl Presentation {
    pub fn new(executor: Executor) -> Self {
        Self { executor, repo: None }
    }
}

impl RPCService for Presentation {
    fn build(&mut self) -> Result<(), CommonError> { 
        self.repo = Some(repository::Repository::new(self.executor.to_owned()));
        Ok(())
    }
}