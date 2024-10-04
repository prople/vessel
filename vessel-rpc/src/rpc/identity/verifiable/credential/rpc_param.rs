use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json::{self, Value};

use prople_did_core::verifiable::objects::VC;
use prople_jsonrpc_client::types::{ExecutorError, RpcValue};

use prople_vessel_core::identity::verifiable::proof::types::Params as ProofParams;
use prople_vessel_core::identity::verifiable::types::PaginationParams;

use crate::rpc::shared::types::CommonError;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(tag = "param", content = "payload")]
pub enum Vessel {
    PostCredential { did_holder: String, vc: VC },
    VerifyCredential { vc: VC },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(tag = "param", content = "payload")]
pub enum Domain {
    GenerateCredential {
        password: String,
        did_issuer: String,
        credential: Value,
        proof_params: Option<ProofParams>,
    },
    SendCredential {
        id: String,
        did_uri: String,
    },
    VerifyCredential {
        id: String,
    },
    ListCredentialsByDID {
        did: String,
        pagination_params: Option<PaginationParams>,
    },
    ListCredentialsByIDs {
        ids: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(tag = "type", content = "payload")]
pub enum Param {
    Vessel(Vessel),
    Domain(Domain),
}

impl RpcValue for Param {
    fn build_serde_value(&self) -> Result<Value, ExecutorError> {
        serde_json::to_value(self).map_err(|err| ExecutorError::BuildValueError(err.to_string()))
    }
}

impl TryFrom<Value> for Param {
    type Error = CommonError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let param: Result<Param, CommonError> =
            serde_json::from_value(value).map_err(|err| CommonError::JSONError(err.to_string()));
        param
    }
}
