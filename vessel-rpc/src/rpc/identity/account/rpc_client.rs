use multiaddr::Multiaddr;

use rst_common::standard::async_trait::async_trait;

use prople_did_core::doc::types::Doc;
use prople_jsonrpc_client::types::Executor;

use prople_vessel_core::identity::account::types::AccountError;
use prople_vessel_core::identity::account::types::RpcBuilder;

use crate::rpc::shared::rpc::build_endpoint;
use crate::rpc::shared::rpc::types::{RpcMethod, RpcMethodVesselAgent, RpcParam};

#[derive(Clone)]
pub struct RpcClient<TExecutor>
where
    TExecutor: Executor<Doc, ErrorData = AccountError>,
{
    client: TExecutor,
}

impl<TExecutor> RpcClient<TExecutor>
where
    TExecutor: Executor<Doc, ErrorData = AccountError>,
{
    pub fn new(client: TExecutor) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<TExecutor> RpcBuilder for RpcClient<TExecutor>
where
    TExecutor: Executor<Doc, ErrorData = AccountError> + Send + Sync + Clone,
{
    async fn resolve_did_doc(&self, addr: Multiaddr, did: String) -> Result<Doc, AccountError> {
        let endpoint =
            build_endpoint(addr).map_err(|err| AccountError::InvalidMultiAddr(err.to_string()))?;

        let rpc_method = RpcMethod::VesselAgent(RpcMethodVesselAgent::ResolveDIDDoc)
            .build_path()
            .path();

        let rpc_param = RpcParam::ResolveDIDDoc { did };
        let rpc_response = self
            .client
            .call(endpoint, rpc_param, rpc_method, None)
            .await.map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        match rpc_response.result {
            Some(doc) => Ok(doc),
            None => Err(AccountError::ResolveDIDError(String::from("missing DID Doc")))
        }
    }
}
