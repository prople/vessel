use prople_jsonrpc_core::types::RpcMethod;

use crate::rpc::shared::rpc::method::RpcMethodBuilder;
use crate::rpc::shared::types::CommonError;

const METHOD_VESSEL_POST_CREDENTIAL: &str = "identity.vc.post_credential";
const METHOD_VESSEL_VERIFY_CREDENTIAL: &str = "identity.vc.verify_credential";

const METHOD_DOMAIN_GENERATE_CREDENTIAL: &str = "identity.vc.generate_credential";
const METHOD_DOMAIN_SEND_CREDENTIAL: &str = "identity.vc.send_credential";
const METHOD_DOMAIN_VERIFY_CREDENTIAL: &str = "identity.vc.verify_credential";
const METHOD_DOMAIN_LIST_CREDENTIALS_BY_DID: &str = "identity.vc.list_credentials_by_did";
const METHOD_DOMAIN_LIST_CREDENTIALS_BY_IDS: &str = "identity.vc.list_credential_by_ids";

#[derive(Clone)]
pub(crate) enum Vessel {
    PostCredential,
    VerifyCredential,
}

impl RpcMethodBuilder for Vessel {
    fn build_path(&self) -> &str {
        match self {
            Vessel::PostCredential => METHOD_VESSEL_POST_CREDENTIAL,
            Vessel::VerifyCredential => METHOD_VESSEL_VERIFY_CREDENTIAL,
        }
    }
}

#[derive(Clone)]
pub(crate) enum Domain {
    GenerateCredential,
    SendCredential,
    VerifyCredential,
    ListCredentialsByDID,
    ListCredentialsByIDs,
}

impl RpcMethodBuilder for Domain {
    fn build_path(&self) -> &str {
        match self {
            Domain::GenerateCredential => METHOD_DOMAIN_GENERATE_CREDENTIAL,
            Domain::ListCredentialsByDID => METHOD_DOMAIN_LIST_CREDENTIALS_BY_DID,
            Domain::ListCredentialsByIDs => METHOD_DOMAIN_LIST_CREDENTIALS_BY_IDS,
            Domain::SendCredential => METHOD_DOMAIN_SEND_CREDENTIAL,
            Domain::VerifyCredential => METHOD_DOMAIN_VERIFY_CREDENTIAL,
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
            Method::Vessel(vessel) => vessel.build_path(),
            Method::Domain(domain) => domain.build_path(),
        }
    }
}

impl TryFrom<RpcMethod> for Method {
    type Error = CommonError;

    fn try_from(value: RpcMethod) -> Result<Self, Self::Error> {
        let given = value.to_string();
        match given.as_str() {
            _ if given.as_str().contains(METHOD_VESSEL_POST_CREDENTIAL) => {
                Ok(Self::Vessel(Vessel::PostCredential))
            }
            _ if given.as_str().contains(METHOD_VESSEL_VERIFY_CREDENTIAL) => {
                Ok(Self::Vessel(Vessel::VerifyCredential))
            }
            _ if given.as_str().contains(METHOD_DOMAIN_GENERATE_CREDENTIAL) => {
                Ok(Self::Domain(Domain::GenerateCredential))
            }
            _ if given
                .as_str()
                .contains(METHOD_DOMAIN_LIST_CREDENTIALS_BY_DID) =>
            {
                Ok(Self::Domain(Domain::ListCredentialsByDID))
            }
            _ if given
                .as_str()
                .contains(METHOD_DOMAIN_LIST_CREDENTIALS_BY_IDS) =>
            {
                Ok(Self::Domain(Domain::ListCredentialsByIDs))
            }
            _ if given.as_str().contains(METHOD_DOMAIN_SEND_CREDENTIAL) => {
                Ok(Self::Domain(Domain::SendCredential))
            }
            _ if given.as_str().contains(METHOD_DOMAIN_VERIFY_CREDENTIAL) => {
                Ok(Self::Domain(Domain::VerifyCredential))
            }
            _ => Err(CommonError::MethodError(format!(
                "unknown method: {}",
                given.to_string()
            ))),
        }
    }
}
