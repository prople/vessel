use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json::{self, Value};

use prople_did_core::verifiable::objects::{VC, VP};
use prople_jsonrpc_client::types::{ExecutorError, RpcValue};

const RPC_METHOD_PREFIX: &str = "prople.vessel";
const RPC_DOMAIN_DID: &str = "did";

pub struct RpcMethodPath(String);

impl RpcMethodPath {
    pub fn path(&self) -> String {
        self.0.clone()
    }
}

pub enum RpcMethodVesselAgent {
    ResolveDIDDoc,
    SendCredentialToHolder,
    VerifyCredentialToIssuer,
    SendToVerifier
}

pub enum RpcMethod {
    VesselAgent(RpcMethodVesselAgent),
}

impl RpcMethod {
    pub fn build_path(&self) -> RpcMethodPath {
        match self {
            RpcMethod::VesselAgent(rpc) => match rpc {
                RpcMethodVesselAgent::ResolveDIDDoc => RpcMethodPath(format!(
                    "{}.{}.resolve_did_docs",
                    RPC_METHOD_PREFIX, RPC_DOMAIN_DID
                )),
                RpcMethodVesselAgent::SendCredentialToHolder => RpcMethodPath(format!(
                    "{}.{}.send_credential_to_holder",
                    RPC_METHOD_PREFIX, RPC_DOMAIN_DID
                )),
                RpcMethodVesselAgent::VerifyCredentialToIssuer => RpcMethodPath(format!(
                    "{}.{}.verify_credential_to_issuer",
                    RPC_METHOD_PREFIX, RPC_DOMAIN_DID
                )),
                RpcMethodVesselAgent::SendToVerifier => RpcMethodPath(format!(
                    "{}.{}.send_to_verifier",
                    RPC_METHOD_PREFIX, RPC_DOMAIN_DID
                )),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
#[serde(tag = "method", content = "payload")]
pub enum RpcParam {
    ResolveDIDDoc { did: String },
    SendCredentialToHolder { did_holder: String, vc: VC },
    VerifyCredentialToIssuer { vc: VC },
    SendToVerifier { did_verifier: String, vp: VP }
}

impl RpcValue for RpcParam {
    fn build_serde_value(&self) -> Result<Value, ExecutorError> {
        serde_json::to_value(self).map_err(|err| ExecutorError::BuildValueError(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rst_common::standard::serde_json::Error;

    #[test]
    fn test_json_serialize_rpc_param() {
        let param = RpcParam::ResolveDIDDoc {
            did: String::from("did:prople:anything"),
        };
        let try_json = serde_json::to_string(&param);

        assert!(!try_json.is_err());

        let jsonstr = try_json.unwrap();
        assert_eq!(
            r#"{"method":"ResolveDIDDoc","payload":{"did":"did:prople:anything"}}"#,
            jsonstr
        )
    }

    #[test]
    fn test_json_deserialize_rpc_param() {
        let jsonstr = r#"{"method":"ResolveDIDDoc","payload":{"did":"did:prople:anything"}}"#;
        let try_rpc_param: Result<RpcParam, Error> = serde_json::from_str(&jsonstr);
        assert!(!try_rpc_param.is_err());

        let did = {
            let param = try_rpc_param.unwrap();
            match param {
                RpcParam::ResolveDIDDoc { did } => did,
                _ => String::from(""),
            }
        };

        assert_eq!(did, "did:prople:anything".to_string())
    }
}
