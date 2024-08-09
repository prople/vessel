use rstdev_storage::engine::rocksdb::executor::Executor;

use crate::rpc::shared::types::{RPCService, CommonError};

pub mod account;
pub mod verifiable;

pub struct Identity {
    db: Executor,
    account: Option<Box<dyn RPCService>>, 
    vc: Option<Box<dyn RPCService>>,
    vp: Option<Box<dyn RPCService>>
}

impl Identity {
    pub fn new(db: Executor) -> Self {
        Self { db, account: None, vc: None, vp: None }
    }
}

impl RPCService for Identity {
    fn build(&mut self) -> Result<(), CommonError> {
        let mut account = account::Account::new(self.db.to_owned());
        account.build()?;

        let mut vc = verifiable::credential::Credential::new(self.db.to_owned());
        vc.build()?;

        let mut vp = verifiable::presentation::Presentation::new(self.db.to_owned());
        vp.build()?;

        self.account = Some(Box::new(account));
        self.vc = Some(Box::new(vc));
        self.vp = Some(Box::new(vp));

        Ok(())
    }
}