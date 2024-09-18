use prople_jsonrpc_core::types::RpcMethod;

use crate::rpc::shared::rpc::method::RpcMethodBuilder;
use crate::rpc::shared::types::CommonError;

const METHOD_VESSEL_POST_PRESENTATION: &str = "identity.vp.post_presentation";

const METHOD_DOMAIN_GENERATE: &str = "identity.vp.generate";
const METHOD_DOMAIN_SEND_PRESENTATION: &str = "identity.vp.send_presentation";
const METHOD_DOMAIN_GET_BY_ID: &str = "identity.vp.get_by_id";
const METHOD_DOMAIN_VERIFY_PRESENTATION: &str = "identity.vp.verify_presentation";
const METHOD_DOMAIN_LIST_VPS_BY_DID_VERIFIER: &str = "identity.vp.list_vps_by_did_verifier";

#[derive(Clone)]
pub(crate) enum Vessel {
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
pub(crate) enum Domain {
    Generate,
    SendPresentation,
    GetByID,
    VerifyPersentation,
    ListVPsByDIDVerifier,
}

impl RpcMethodBuilder for Domain {
    fn build_path(&self) -> &str {
        match self {
            Domain::Generate => METHOD_DOMAIN_GENERATE,
            Domain::SendPresentation => METHOD_DOMAIN_SEND_PRESENTATION,
            Domain::GetByID => METHOD_DOMAIN_GET_BY_ID,
            Domain::VerifyPersentation => METHOD_DOMAIN_VERIFY_PRESENTATION,
            Domain::ListVPsByDIDVerifier => METHOD_DOMAIN_LIST_VPS_BY_DID_VERIFIER,
        }
    }
}

#[derive(Clone)]
pub(crate) enum Method {
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
                .contains(METHOD_DOMAIN_LIST_VPS_BY_DID_VERIFIER) =>
            {
                Ok(Self::Domain(Domain::ListVPsByDIDVerifier))
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
