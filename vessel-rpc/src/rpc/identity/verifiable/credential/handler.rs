use rst_common::standard::async_trait::async_trait;
use rst_common::standard::serde_json::Value;

use prople_jsonrpc_core::types::{RpcError, RpcHandler, RpcHandlerOutput, RpcMethod};

use prople_vessel_core::identity::verifiable::credential::types::CredentialAPI;
use prople_vessel_core::identity::verifiable::{Credential, Holder};

use super::rpc_method::{Domain as DomainMethod, Method, Vessel as VesselMethod};
use super::rpc_param::{Domain, Param, Vessel as VesselParam};

#[derive(Clone)]
pub struct CredentialHandler<TCredential>
where
    TCredential: CredentialAPI<EntityAccessor = Credential>,
{
    credential_api: TCredential,
}

impl<TCredential> CredentialHandler<TCredential>
where
    TCredential: CredentialAPI<EntityAccessor = Credential, HolderEntityAccessor = Holder>,
{
    pub fn new(credential_api: TCredential) -> Self {
        Self { credential_api }
    }

    async fn generate_credential(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::GenerateCredential {
                    password,
                    did_issuer,
                    credential,
                } => {
                    let result = self
                        .credential_api
                        .generate_credential(password, did_issuer, credential)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn send_credential_to_holder(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::SendCredential {
                    id,
                    did_uri,
                    password,
                    params,
                } => {
                    let _ = self
                        .credential_api
                        .send_credential(id, did_uri, password, params)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(None)
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn receive_credential_by_holder(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Vessel(vessel) => match vessel {
                VesselParam::PostCredential { did_holder, vc } => {
                    let _ = self
                        .credential_api
                        .post_credential(did_holder, vc)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(None)
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn list_credentials_by_did(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::ListCredentialsByDID {
                    did,
                    pagination_params,
                } => {
                    let result = self
                        .credential_api
                        .list_credentials_by_did(did, pagination_params)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn list_credentials_by_ids(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::ListCredentialsByIDs { ids } => {
                    let result = self
                        .credential_api
                        .list_credentials_by_ids(ids)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn list_holders_by_did(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::ListHoldersByDID {
                    did,
                    pagination_params,
                } => {
                    let result = self
                        .credential_api
                        .list_holders_by_did(did, pagination_params)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn list_holders_by_ids(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::ListHoldersByIDs { ids } => {
                    let result = self
                        .credential_api
                        .list_holders_by_ids(ids)
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
impl<TCredential> RpcHandler for CredentialHandler<TCredential>
where
    TCredential: CredentialAPI<EntityAccessor = Credential, HolderEntityAccessor = Holder> + Send + Sync,
{
    async fn call(&self, method: RpcMethod, params: Option<Value>) -> RpcHandlerOutput {
        let rpc_method = Method::try_from(method).map_err(|_| RpcError::InternalError)?;
        let param_value = params.ok_or(RpcError::InvalidParams)?;
        let rpc_param = Param::try_from(param_value).map_err(|_| RpcError::ParseError)?;

        match rpc_method {
            Method::Vessel(vessel) => match vessel {
                VesselMethod::PostCredential => self.receive_credential_by_holder(rpc_param).await,
                _ => Err(RpcError::MethodNotFound),
            },
            Method::Domain(domain) => match domain {
                DomainMethod::GenerateCredential => self.generate_credential(rpc_param).await,
                DomainMethod::ListCredentialsByDID => self.list_credentials_by_did(rpc_param).await,
                DomainMethod::ListCredentialsByIDs => self.list_credentials_by_ids(rpc_param).await,
                DomainMethod::SendCredential => self.send_credential_to_holder(rpc_param).await,
                DomainMethod::ListHoldersByDID => self.list_holders_by_did(rpc_param).await,
                DomainMethod::ListHoldersByIDs => self.list_holders_by_ids(rpc_param).await,
            },
        }
    }
}
