use rstdev_storage::engine::rocksdb::executor::Executor as DbExecutor;

use prople_did_core::doc::types::Doc;
use prople_jsonrpc_client::executor::reqwest::Reqwest as ReqwestExecutor;

use prople_jsonrpc_core::types::RpcRoute;

use prople_vessel_core::identity::account::types::AccountAPI;
use prople_vessel_core::identity::account::usecase::Usecase;

use crate::rpc::shared::rpc::method::build_rpc_method;
use crate::rpc::shared::types::{CommonError, RPCService};

mod handler;
mod repository;
mod rpc_client;
mod rpc_method;
mod rpc_param;

pub use handler::AccountHandler;
pub use repository::Repository;

pub use rpc_client::RpcClient;

pub mod components {
    use super::*;

    pub use prople_jsonrpc_core::types::RpcError as CoreRpcError;
    pub use prople_vessel_core::identity::account::Account as CoreAccountModel;

    pub use rpc_method::Method;
    pub use rpc_param::{Domain as ParamDomain, Param, Vessel as ParamVessel};
}

type AccountRpcClient = RpcClient<ReqwestExecutor<Doc>>;
type AccountAPIImplementer = Usecase<Repository, AccountRpcClient>;

pub struct Account<TAccount>
where
    TAccount: AccountAPI,
{
    db_executor: DbExecutor,
    repo: Option<Repository>,
    rpc_client: Option<AccountRpcClient>,
    domain_api: Option<TAccount>,
    routes: Vec<RpcRoute>,
}

impl<TAccount> Account<TAccount>
where
    TAccount: AccountAPI,
{
    pub fn new(db_executor: DbExecutor) -> Self {
        Self {
            db_executor,
            repo: None,
            rpc_client: None,
            domain_api: None,
            routes: Vec::new(),
        }
    }
}

impl RPCService for Account<AccountAPIImplementer> {
    fn build(&mut self) -> Result<(), CommonError> {
        let repo = Repository::new(self.db_executor.to_owned());
        let rpc = RpcClient::new(ReqwestExecutor::new());

        self.repo = Some(repo.clone());
        self.rpc_client = Some(rpc.clone());

        let usecase = Usecase::new(repo, rpc);
        self.domain_api = Some(usecase);
        Ok(())
    }

    fn setup_rpc(&mut self) -> Result<(), CommonError> {
        let usecase = self
            .domain_api
            .as_ref()
            .ok_or(CommonError::InternalError(String::from(
                "missing account usecase",
            )))?;

        let handler = AccountHandler::new(usecase.clone());
        let controller = Box::new(handler);

        self.routes.push(RpcRoute::new(
            build_rpc_method(components::Method::GenerateDID),
            controller.clone(),
        ));
        self.routes.push(RpcRoute::new(
            build_rpc_method(components::Method::BuildDIDURI),
            controller.clone(),
        ));
        self.routes.push(RpcRoute::new(
            build_rpc_method(components::Method::ResolveDIDURI),
            controller.clone(),
        ));
        self.routes.push(RpcRoute::new(
            build_rpc_method(components::Method::ResolveDIDDoc),
            controller.clone(),
        ));
        self.routes.push(RpcRoute::new(
            build_rpc_method(components::Method::RemoveDID),
            controller.clone(),
        ));
        self.routes.push(RpcRoute::new(
            build_rpc_method(components::Method::GetAccountDID),
            controller.clone(),
        ));

        Ok(())
    }

    fn routes(&self) -> Vec<RpcRoute> {
        self.routes.clone()
    }
}
