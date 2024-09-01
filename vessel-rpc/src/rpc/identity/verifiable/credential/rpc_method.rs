use prople_jsonrpc_core::types::RpcMethod;

use crate::rpc::shared::rpc::method::RpcMethodBuilder;
use crate::rpc::shared::types::CommonError;

const METHOD_VESSEL_RECEIVE_CREDENTIAL_BY_HOLDER: &str = "identity.vc.receive_credential_by_holder";
const METHOD_VESSEL_VERIFY_CREDENTIAL_TO_ISSUER: &str = "identity.vc.verify_credential_to_issuer";

const METHOD_DOMAIN_GENERATE_CREDENTIAL: &str = "identity.vc.generate_credential";
const METHOD_DOMAIN_SEND_CREDENTIAL_TO_HOLDER: &str = "identity.vc.send_credential_to_holder";
const METHOD_DOMAIN_VERIFY_CREDENTIAL_BY_HOLDER: &str = "identity.vc.verify_credential_by_holder";
const METHOD_DOMAIN_LIST_CREDENTIALS_BY_DID: &str = "identity.vc.list_credentials_by_did";
const METHOD_DOMAIN_LIST_CREDENTIALS_BY_IDS: &str = "identity.vc.list_credential_by_ids";

#[derive(Clone)]
pub(crate) enum Vessel {
    ReceiveCredentialByHolder,
    VerifyCredentialToIssuer,
}

impl RpcMethodBuilder for Vessel {
    fn build_path(&self) -> &str {
        match self {
            Vessel::ReceiveCredentialByHolder => METHOD_VESSEL_RECEIVE_CREDENTIAL_BY_HOLDER,
            Vessel::VerifyCredentialToIssuer => METHOD_VESSEL_VERIFY_CREDENTIAL_TO_ISSUER,
        }
    }
}

#[derive(Clone)]
pub(crate) enum Domain {
    GenerateCredential,
    SendCredentialToHolder,
    VerifyCredentialByHolder,
    ListCredentialsByDID,
    ListCredentialsByIDs,
}

impl RpcMethodBuilder for Domain {
    fn build_path(&self) -> &str {
        match self {
            Domain::GenerateCredential => METHOD_DOMAIN_GENERATE_CREDENTIAL,
            Domain::ListCredentialsByDID => METHOD_DOMAIN_LIST_CREDENTIALS_BY_DID,
            Domain::ListCredentialsByIDs => METHOD_DOMAIN_LIST_CREDENTIALS_BY_IDS,
            Domain::SendCredentialToHolder => METHOD_DOMAIN_SEND_CREDENTIAL_TO_HOLDER,
            Domain::VerifyCredentialByHolder => METHOD_DOMAIN_VERIFY_CREDENTIAL_BY_HOLDER,
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
            _ if given
                .as_str()
                .contains(METHOD_VESSEL_RECEIVE_CREDENTIAL_BY_HOLDER) =>
            {
                Ok(Self::Vessel(Vessel::ReceiveCredentialByHolder))
            }
            _ if given
                .as_str()
                .contains(METHOD_VESSEL_VERIFY_CREDENTIAL_TO_ISSUER) =>
            {
                Ok(Self::Vessel(Vessel::VerifyCredentialToIssuer))
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
            _ if given
                .as_str()
                .contains(METHOD_DOMAIN_SEND_CREDENTIAL_TO_HOLDER) =>
            {
                Ok(Self::Domain(Domain::SendCredentialToHolder))
            }
            _ if given
                .as_str()
                .contains(METHOD_DOMAIN_VERIFY_CREDENTIAL_BY_HOLDER) =>
            {
                Ok(Self::Domain(Domain::VerifyCredentialByHolder))
            }
            _ => Err(CommonError::MethodError(format!(
                "unknown method: {}",
                given.to_string()
            ))),
        }
    }
}
