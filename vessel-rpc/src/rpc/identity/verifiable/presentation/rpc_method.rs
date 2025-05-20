use prople_jsonrpc_core::types::RpcMethod;

use crate::rpc::shared::rpc::method::RpcMethodBuilder;
use crate::rpc::shared::types::CommonError;

const METHOD_VESSEL_POST_PRESENTATION: &str = "identity.vp.post_presentation";

const METHOD_DOMAIN_GENERATE: &str = "identity.vp.generate";
const METHOD_DOMAIN_SEND_PRESENTATION: &str = "identity.vp.send_presentation";
const METHOD_DOMAIN_GET_BY_ID: &str = "identity.vp.get_by_id";
const METHOD_DOMAIN_VERIFY_PRESENTATION: &str = "identity.vp.verify_presentation";
const METHOD_DOMAIN_LIST_VERIFIERS_BY_DID: &str = "identity.vp.list_verifiers_by_did";

#[derive(Clone)]
pub enum Vessel {
    PostPresentation,
}

impl RpcMethodBuilder for Vessel {
    fn build_path(&self) -> &str {
        match self {
            Vessel::PostPresentation => METHOD_VESSEL_POST_PRESENTATION,
        }
    }
}

#[derive(Clone)]
pub enum Domain {
    Generate,
    SendPresentation,
    GetByID,
    VerifyPersentation,
    ListVerifiersByDID,
}

impl RpcMethodBuilder for Domain {
    fn build_path(&self) -> &str {
        match self {
            Domain::Generate => METHOD_DOMAIN_GENERATE,
            Domain::SendPresentation => METHOD_DOMAIN_SEND_PRESENTATION,
            Domain::GetByID => METHOD_DOMAIN_GET_BY_ID,
            Domain::VerifyPersentation => METHOD_DOMAIN_VERIFY_PRESENTATION,
            Domain::ListVerifiersByDID => METHOD_DOMAIN_LIST_VERIFIERS_BY_DID,
        }
    }
}

#[derive(Clone)]
pub enum Method {
    Vessel(Vessel),
    Domain(Domain),
}

impl RpcMethodBuilder for Method {
    fn build_path(&self) -> &str {
        match self {
            Method::Domain(domain) => domain.build_path(),
            Method::Vessel(vessel) => vessel.build_path(),
        }
    }
}

impl TryFrom<RpcMethod> for Method {
    type Error = CommonError;

    fn try_from(value: RpcMethod) -> Result<Self, Self::Error> {
        let given = value.to_string();
        match given.as_str() {
            _ if given.as_str().contains(METHOD_VESSEL_POST_PRESENTATION) => {
                Ok(Self::Vessel(Vessel::PostPresentation))
            }
            _ if given.as_str().contains(METHOD_DOMAIN_GENERATE) => {
                Ok(Self::Domain(Domain::Generate))
            }
            _ if given.as_str().contains(METHOD_DOMAIN_GET_BY_ID) => {
                Ok(Self::Domain(Domain::GetByID))
            }
            _ if given
                .as_str()
                .contains(METHOD_DOMAIN_LIST_VERIFIERS_BY_DID) =>
            {
                Ok(Self::Domain(Domain::ListVerifiersByDID))
            }
            _ if given.as_str().contains(METHOD_DOMAIN_SEND_PRESENTATION) => {
                Ok(Self::Domain(Domain::SendPresentation))
            }
            _ if given.as_str().contains(METHOD_DOMAIN_VERIFY_PRESENTATION) => {
                Ok(Self::Domain(Domain::VerifyPersentation))
            }
            _ => Err(CommonError::MethodError(format!(
                "unknown method: {}",
                given.to_string()
            ))),
        }
    }
}
