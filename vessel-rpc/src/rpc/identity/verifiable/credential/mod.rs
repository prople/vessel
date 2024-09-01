use rstdev_storage::engine::rocksdb::executor::Executor;

use prople_did_core::doc::types::Doc;

use prople_jsonrpc_client::executor::reqwest::Reqwest as ReqwestExecutor;
use prople_jsonrpc_core::types::RpcRoute;

use prople_vessel_core::identity::account::types::AccountError;
use prople_vessel_core::identity::account::usecase::Usecase as AccountUsecase;

use prople_vessel_core::identity::verifiable::credential::types::{CredentialAPI, CredentialError};
use prople_vessel_core::identity::verifiable::credential::Usecase as CredentialUsecase;

use crate::rpc::identity::account::{Repository as AccountRepo, RpcClient as AccountRpc};

use crate::rpc::shared::rpc::method::build_rpc_method;
use crate::rpc::shared::types::{CommonError, RPCService};

use super::credential::rpc_method::{Domain, Method, Vessel};

mod handler;
mod repository;
mod rpc_client;
mod rpc_method;
mod rpc_param;

pub use handler::CredentialHandler;
pub use repository::Repository;
pub use rpc_client::RpcClient;

type AccountRpcClient = AccountRpc<ReqwestExecutor<Doc, AccountError>>;
type AccountAPIImplementer = AccountUsecase<AccountRepo, AccountRpcClient>;

type CredentialRpcClient = RpcClient<ReqwestExecutor<(), CredentialError>>;
type CredentialAPIImplementer =
    CredentialUsecase<CredentialRpcClient, Repository, AccountAPIImplementer>;

pub struct Credential<TCredential>
where
    TCredential: CredentialAPI,
{
    executor: Executor,
    repo: Option<Repository>,
    rpc_client: Option<CredentialRpcClient>,
    credential_api: Option<TCredential>,
    routes: Vec<RpcRoute>,
}

impl<TCredential> Credential<TCredential>
where
    TCredential: CredentialAPI,
{
    pub fn new(executor: Executor) -> Self {
        Self {
            executor,
            repo: None,
            rpc_client: None,
            credential_api: None,
            routes: Vec::new(),
        }
    }
}

impl RPCService for Credential<CredentialAPIImplementer> {
    fn build(&mut self) -> Result<(), CommonError> {
        let repo = Repository::new(self.executor.to_owned());
        self.repo = Some(repo.clone());

        let rpc = RpcClient::new(ReqwestExecutor::new());
        self.rpc_client = Some(rpc.clone());

        let account_repo = AccountRepo::new(self.executor.clone());
        let account_rpc = AccountRpc::new(ReqwestExecutor::new());
        let account_usecase = AccountUsecase::new(account_repo, account_rpc);

        let usecase = CredentialUsecase::new(repo, rpc, account_usecase);
        self.credential_api = Some(usecase);
        Ok(())
    }

    fn setup_rpc(&mut self) -> Result<(), CommonError> {
        let usecase = self
            .credential_api
            .as_ref()
            .ok_or(CommonError::InternalError(String::from(
                "missing credential usecase",
            )))?;

        let handler = CredentialHandler::new(usecase.clone());
        let controller = Box::new(handler);

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Vessel(Vessel::ReceiveCredentialByHolder)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::GenerateCredential)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::ListCredentialsByDID)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::ListCredentialsByIDs)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::SendCredentialToHolder)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::VerifyCredentialByHolder)),
            controller.clone(),
        ));

        Ok(())
    }

    fn routes(&self) -> Vec<RpcRoute> {
        self.routes.clone()
    }
}
