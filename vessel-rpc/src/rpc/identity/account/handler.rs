use rst_common::standard::async_trait::async_trait;
use rst_common::standard::serde_json::Value;

use prople_jsonrpc_core::types::{RpcError, RpcHandler, RpcHandlerOutput, RpcMethod};

use prople_vessel_core::identity::account::types::AccountAPI;
use prople_vessel_core::identity::account::Account;

use super::rpc_method::Method;
use super::rpc_param::{Domain, Param};

#[derive(Clone)]
pub struct AccountHandler<TAccount>
where
    TAccount: AccountAPI<EntityAccessor = Account>,
{
    account_api: TAccount,
}

impl<TAccount> AccountHandler<TAccount>
where
    TAccount: AccountAPI<EntityAccessor = Account>,
{
    pub fn new(account_api: TAccount) -> Self {
        Self { account_api }
    }

    async fn generate_did(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::GenerateDID { password } => {
                    let result = self
                        .account_api
                        .generate_did(password)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;
                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn build_did_uri(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::BuildDIDURI {
                    did,
                    password,
                    query_params,
                } => {
                    let result = self
                        .account_api
                        .build_did_uri(did, password, query_params)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn resolve_did_uri(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::ResolveDIDURI { uri } => {
                    let result = self
                        .account_api
                        .resolve_did_uri(uri)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn resolve_did_doc(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::ResolveDIDDoc { did } => {
                    let result = self
                        .account_api
                        .resolve_did_doc(did)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn remove_did(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::RemoveDID { did } => {
                    let _ = self
                        .account_api
                        .remove_did(did)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(None)
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn get_account_did(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::GetAccountDID { did } => {
                    let result = self
                        .account_api
                        .get_account_did(did)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }
}

#[async_trait]
impl<TAccount> RpcHandler for AccountHandler<TAccount>
where
    TAccount: AccountAPI<EntityAccessor = Account> + Send + Sync,
{
    async fn call(&self, method: RpcMethod, params: Option<Value>) -> RpcHandlerOutput {
        let param_value = params.ok_or(RpcError::InvalidParams)?;
        let rpc_param = Param::try_from(param_value).map_err(|_| RpcError::ParseError)?;
        let rpc_method = Method::try_from(method).map_err(|_| RpcError::InternalError)?;

        match rpc_method {
            Method::GenerateDID => self.generate_did(rpc_param).await,
            Method::BuildDIDURI => self.build_did_uri(rpc_param).await,
            Method::ResolveDIDURI => self.resolve_did_uri(rpc_param).await,
            Method::ResolveDIDDoc => self.resolve_did_doc(rpc_param).await,
            Method::RemoveDID => self.remove_did(rpc_param).await,
            Method::GetAccountDID => self.get_account_did(rpc_param).await,
        }
    }
}
