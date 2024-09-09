use rstdev_storage::engine::rocksdb::executor::Executor;

use prople_jsonrpc_client::executor::reqwest::Reqwest as ReqwestExecutor;
use prople_jsonrpc_core::types::RpcRoute;

use prople_did_core::doc::types::Doc;

use prople_vessel_core::identity::account::types::AccountError;
use prople_vessel_core::identity::account::usecase::Usecase as AccountUsecase;

use prople_vessel_core::identity::verifiable::credential::types::CredentialError;
use prople_vessel_core::identity::verifiable::credential::Usecase as CredentialUsecase;

use prople_vessel_core::identity::verifiable::presentation::types::{
    PresentationAPI, PresentationError,
};
use prople_vessel_core::identity::verifiable::presentation::usecase::Usecase as PresentationUsecase;

use crate::rpc::identity::account::{Repository as AccountRepo, RpcClient as AccountRpc};
use crate::rpc::identity::verifiable::credential::{
    Repository as CredentialRepo, RpcClient as CredentialRpc,
};

use super::presentation::rpc_method::{Domain, Method, Vessel};

use crate::rpc::shared::rpc::method::build_rpc_method;
use crate::rpc::shared::types::{CommonError, RPCService};

mod handler;
mod repository;
mod rpc_client;
mod rpc_method;
mod rpc_param;

pub use handler::PresentationHandler;
pub use repository::Repository;
pub use rpc_client::RpcClient;

type AccountRpcClient = AccountRpc<ReqwestExecutor<Doc, AccountError>>;
type AccountAPIImplementer = AccountUsecase<AccountRepo, AccountRpcClient>;

type CredentialRpcClient = CredentialRpc<ReqwestExecutor<(), CredentialError>>;
type CredentialAPIImplementer =
    CredentialUsecase<CredentialRpcClient, CredentialRepo, AccountAPIImplementer>;

type PresentationRpcClient = RpcClient<ReqwestExecutor<(), PresentationError>>;
type PresentationAPIImplementer = PresentationUsecase<
    PresentationRpcClient,
    Repository,
    AccountAPIImplementer,
    CredentialAPIImplementer,
>;

pub struct Presentation<TPresentation>
where
    TPresentation: PresentationAPI,
{
    executor: Executor,
    repo: Option<Repository>,
    rpc_client: Option<PresentationRpcClient>,
    presentation_api: Option<TPresentation>,
    routes: Vec<RpcRoute>,
}

impl<TPresentation> Presentation<TPresentation>
where
    TPresentation: PresentationAPI,
{
    pub fn new(executor: Executor) -> Self {
        Self {
            executor,
            repo: None,
            rpc_client: None,
            presentation_api: None,
            routes: Vec::new(),
        }
    }
}

impl RPCService for Presentation<PresentationAPIImplementer> {
    fn build(&mut self) -> Result<(), CommonError> {
        let repo = Repository::new(self.executor.to_owned());
        self.repo = Some(repo);

        let rpc_client = RpcClient::new(ReqwestExecutor::new());
        self.rpc_client = Some(rpc_client);

        let account_repo = AccountRepo::new(self.executor.clone());
        let account_rpc = AccountRpc::new(ReqwestExecutor::new());
        let account_usecase = AccountUsecase::new(account_repo, account_rpc);

        let credential_repo = CredentialRepo::new(self.executor.clone());
        let credential_rpc = CredentialRpc::new(ReqwestExecutor::new());
        let credential_usecase =
            CredentialUsecase::new(credential_repo, credential_rpc, account_usecase.clone());

        let presentation_repo = Repository::new(self.executor.clone());
        let presentation_rpc = RpcClient::new(ReqwestExecutor::new());
        let presentation_usecase = PresentationUsecase::new(
            presentation_repo,
            presentation_rpc,
            account_usecase,
            credential_usecase,
        );

        self.presentation_api = Some(presentation_usecase);
        Ok(())
    }

    fn setup_rpc(&mut self) -> Result<(), CommonError> {
        let usecase = self
            .presentation_api
            .as_ref()
            .ok_or(CommonError::InternalError(String::from(
                "missing presentation usecase",
            )))?;

        let handler = PresentationHandler::new(usecase.clone());
        let controller = Box::new(handler);

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Vessel(Vessel::PostPresentation)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::Generate)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::GetByID)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::ListVPsByDIDVerifier)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::SendPresentation)),
            controller.clone(),
        ));

        self.routes.push(RpcRoute::new(
            build_rpc_method(Method::Domain(Domain::VerifyPersentation)),
            controller.clone(),
        ));

        Ok(())
    }

    fn routes(&self) -> Vec<RpcRoute> {
        self.routes.clone()
    }
}
