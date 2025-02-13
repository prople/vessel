use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json::{self, Value};

use prople_did_core::verifiable::objects::VP;
use prople_jsonrpc_client::types::{ExecutorError, RpcValue};

use crate::rpc::shared::types::CommonError;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(tag = "param", content = "payload")]
pub enum Vessel {
    PostPresentation { did_verifier: String, vp: VP },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(tag = "param", content = "payload")]
pub enum Domain {
    Generate {
        password: String,
        did_issuer: String,
        credentials: Vec<String>,
    },
    SendPresentation {
        id: String,
        did_uri: String,
    },
    VerifyPresentation {
        id: String,
    },
    GetByID {
        id: String,
    },
    ListVPsByDIDVerifier {
        did_verifier: String,
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
