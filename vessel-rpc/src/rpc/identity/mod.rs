use rstdev_storage::engine::rocksdb::executor::Executor;

use prople_jsonrpc_core::types::RpcRoute;

use crate::rpc::shared::types::{CommonError, RPCService};

use super::identity::account::Account as RpcAccount;
use super::identity::verifiable::credential::Credential as RpcCredential;
use super::identity::verifiable::presentation::Presentation as RpcPresentation;

pub mod account;
pub mod verifiable;

pub struct Identity {
    db: Executor,
    account: Option<Box<dyn RPCService>>,
    vc: Option<Box<dyn RPCService>>,
    vp: Option<Box<dyn RPCService>>,
    routes: Vec<RpcRoute>,
}

impl Identity {
    pub fn new(db: Executor) -> Self {
        Self {
            db,
            account: None,
            vc: None,
            vp: None,
            routes: Vec::new(),
        }
    }
}

impl RPCService for Identity {
    fn build(&mut self) -> Result<(), CommonError> {
        let mut account = RpcAccount::new(self.db.to_owned());
        account.build()?;

        let mut vc = RpcCredential::new(self.db.to_owned());
        vc.build()?;

        let mut vp = RpcPresentation::new(self.db.to_owned());
        vp.build()?;

        self.account = Some(Box::new(account));
        self.vc = Some(Box::new(vc));
        self.vp = Some(Box::new(vp));

        Ok(())
    }

    fn setup_rpc(&mut self) -> Result<(), CommonError> {
        Ok(())
    }

    fn routes(&self) -> Vec<RpcRoute> {
        self.routes.clone()
    }
}
