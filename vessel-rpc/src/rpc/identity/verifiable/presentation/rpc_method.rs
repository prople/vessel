use prople_jsonrpc_core::types::RpcMethod;

use crate::rpc::shared::rpc::method::RpcMethodBuilder;
use crate::rpc::shared::types::CommonError;

const METHOD_VESSEL_RECEIVE_PRESENTATION_BY_VERIFIER: &str =
    "identity.vp.receive_presentation_by_verifier";

const METHOD_DOMAIN_GENERATE: &str = "identity.vp.generate";
const METHOD_DOMAIN_SEND_TO_VERIFIER: &str = "identity.vp.send_to_verifier";
const METHOD_DOMAIN_GET_BY_ID: &str = "identity.vp.get_by_id";
const METHOD_DOMAIN_VERIFY_PRESENTATION_BY_VERIFIER: &str =
    "identity.vp.verify_presentation_by_verifier";
const METHOD_DOMAIN_LIST_VPS_BY_DID_VERIFIER: &str = "identity.vp.list_vps_by_did_verifier";

#[derive(Clone)]
pub(crate) enum Vessel {
    ReceivePresentationByVerifier,
}

impl RpcMethodBuilder for Vessel {
    fn build_path(&self) -> &str {
        match self {
            Vessel::ReceivePresentationByVerifier => METHOD_VESSEL_RECEIVE_PRESENTATION_BY_VERIFIER,
        }
    }
}

#[derive(Clone)]
pub(crate) enum Domain {
    Generate,
    SendToVerifier,
    GetByID,
    VerifyPersentationByVerifier,
    ListVPsByDIDVerifier,
}

impl RpcMethodBuilder for Domain {
    fn build_path(&self) -> &str {
        match self {
            Domain::Generate => METHOD_DOMAIN_GENERATE,
            Domain::SendToVerifier => METHOD_DOMAIN_SEND_TO_VERIFIER,
            Domain::GetByID => METHOD_DOMAIN_GET_BY_ID,
            Domain::VerifyPersentationByVerifier => METHOD_DOMAIN_VERIFY_PRESENTATION_BY_VERIFIER,
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
            _ if given
                .as_str()
                .contains(METHOD_VESSEL_RECEIVE_PRESENTATION_BY_VERIFIER) =>
            {
                Ok(Self::Vessel(Vessel::ReceivePresentationByVerifier))
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
            _ if given.as_str().contains(METHOD_DOMAIN_SEND_TO_VERIFIER) => {
                Ok(Self::Domain(Domain::SendToVerifier))
            }
            _ if given
                .as_str()
                .contains(METHOD_DOMAIN_VERIFY_PRESENTATION_BY_VERIFIER) =>
            {
                Ok(Self::Domain(Domain::VerifyPersentationByVerifier))
            }
            _ => Err(CommonError::MethodError(format!(
                "unknown method: {}",
                given.to_string()
            ))),
        }
    }
}
