use rst_common::standard::async_trait::async_trait;
use rst_common::standard::serde_json::Value;

use prople_jsonrpc_core::types::{RpcError, RpcHandler, RpcHandlerOutput, RpcMethod};

use prople_vessel_core::identity::verifiable::presentation::types::PresentationAPI;
use prople_vessel_core::identity::verifiable::presentation::{Presentation, Verifier};

use super::rpc_method::{Domain as DomainMethod, Method, Vessel as VesselMethod};
use super::rpc_param::{Domain, Param, Vessel as VesselParam};

#[derive(Clone)]
pub struct PresentationHandler<TPresentation>
where
    TPresentation: PresentationAPI<
        PresentationEntityAccessor = Presentation,
        VerifierEntityAccessor = Verifier,
    >,
{
    presentation_api: TPresentation,
}

impl<TPresentation> PresentationHandler<TPresentation>
where
    TPresentation: PresentationAPI<
        PresentationEntityAccessor = Presentation,
        VerifierEntityAccessor = Verifier,
    >,
{
    pub fn new(presentation_api: TPresentation) -> Self {
        Self { presentation_api }
    }

    async fn generate(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::Generate {
                    password,
                    did_issuer,
                    credentials,
                    proof_params,
                } => {
                    let result = self
                        .presentation_api
                        .generate(password, did_issuer, credentials, proof_params)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn send_to_verifier(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::SendToVerifier { id, did_uri } => {
                    let _ = self
                        .presentation_api
                        .send_to_verifier(id, did_uri)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(None)
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn verify_presentation_by_verifier(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::VerifyPresentationByVerifier { id } => {
                    let _ = self
                        .presentation_api
                        .verify_presentation_by_verifier(id)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(None)
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn get_by_id(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::GetByID { id } => {
                    let result = self
                        .presentation_api
                        .get_by_id(id)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(Some(Box::new(result)))
                }
                _ => Err(RpcError::InvalidParams),
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn receive_presentation_by_verifier(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Vessel(vessel) => match vessel {
                VesselParam::ReceivePresentationByVerifier { did_verifier, vp } => {
                    let _ = self
                        .presentation_api
                        .receive_presentation_by_verifier(did_verifier, vp)
                        .await
                        .map_err(|err| RpcError::HandlerError(err.to_string()))?;

                    Ok(None)
                }
            },
            _ => Err(RpcError::InvalidParams),
        }
    }

    async fn list_vps_by_did_verifier(&self, param: Param) -> RpcHandlerOutput {
        match param {
            Param::Domain(domain) => match domain {
                Domain::ListVPsByDIDVerifier { did_verifier } => {
                    let result = self
                        .presentation_api
                        .list_vps_by_did_verifier(did_verifier)
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
impl<TPresentation> RpcHandler for PresentationHandler<TPresentation>
where
    TPresentation: PresentationAPI<
            PresentationEntityAccessor = Presentation,
            VerifierEntityAccessor = Verifier,
        > + Send
        + Sync,
{
    async fn call(&self, method: RpcMethod, params: Value) -> RpcHandlerOutput {
        let rpc_method = Method::try_from(method).map_err(|_| RpcError::InternalError)?;
        let rpc_param = Param::try_from(params).map_err(|_| RpcError::ParseError)?;

        match rpc_method {
            Method::Vessel(vessel) => match vessel {
                VesselMethod::ReceivePresentationByVerifier => {
                    self.receive_presentation_by_verifier(rpc_param).await
                }
            },
            Method::Domain(domain) => match domain {
                DomainMethod::Generate => self.generate(rpc_param).await,
                DomainMethod::GetByID => self.get_by_id(rpc_param).await,
                DomainMethod::ListVPsByDIDVerifier => {
                    self.list_vps_by_did_verifier(rpc_param).await
                }
                DomainMethod::SendToVerifier => self.send_to_verifier(rpc_param).await,
                DomainMethod::VerifyPersentationByVerifier => {
                    self.verify_presentation_by_verifier(rpc_param).await
                }
            },
        }
    }
}
