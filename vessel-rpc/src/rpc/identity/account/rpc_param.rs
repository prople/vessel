use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json::{self, Value};

use prople_did_core::did::query::Params as QueryParams;
use prople_jsonrpc_client::types::{ExecutorError, RpcValue};

use crate::rpc::shared::types::CommonError;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(tag = "param", content = "payload")]
pub enum Vessel {
    ResolveDIDDoc { did: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
#[serde(tag = "param", content = "payload")]
pub enum Domain {
    GenerateDID {
        password: String,
    },
    BuildDIDURI {
        did: String,
        password: String,
        query_params: Option<QueryParams>,
    },
    ResolveDIDURI {
        uri: String,
    },
    ResolveDIDDoc {
        did: String,
    },
    RemoveDID {
        did: String,
    },
    GetAccountDID {
        did: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    use rst_common::standard::serde_json;

    #[test]
    fn test_build_vessel_serde_json_str() {
        let param = Param::Vessel(Vessel::ResolveDIDDoc {
            did: String::from("test"),
        });
        let try_json = serde_json::to_string(&param);
        assert!(!try_json.is_err());

        let expected =
            r#"{"type":"Vessel","payload":{"param":"ResolveDIDDoc","payload":{"did":"test"}}}"#;
        assert_eq!(expected, try_json.unwrap())
    }

    #[test]
    fn test_build_domain_serde_json_str() {
        let param = Param::Domain(Domain::GenerateDID {
            password: String::from("password"),
        });
        let try_json = serde_json::to_string(&param);
        assert!(!try_json.is_err());

        let expected = r#"{"type":"Domain","payload":{"param":"GenerateDID","payload":{"password":"password"}}}"#;
        assert_eq!(expected, try_json.unwrap())
    }

    #[test]
    fn test_vessel_from_str() {
        let jsonstr =
            r#"{"type":"Vessel","payload":{"param":"ResolveDIDDoc","payload":{"did":"test"}}}"#;

        let value: Result<Param, CommonError> =
            serde_json::from_str(&jsonstr).map_err(|err| CommonError::JSONError(err.to_string()));
        assert!(!value.is_err());
        assert!(matches!(
            value.unwrap(),
            Param::Vessel(Vessel::ResolveDIDDoc { .. })
        ))
    }

    #[test]
    fn test_domain_from_str() {
        let jsonstr = r#"{"type":"Domain","payload":{"param":"GenerateDID","payload":{"password":"password"}}}"#;

        let value: Result<Param, CommonError> =
            serde_json::from_str(&jsonstr).map_err(|err| CommonError::JSONError(err.to_string()));
        assert!(!value.is_err());
        assert!(matches!(
            value.unwrap(),
            Param::Domain(Domain::GenerateDID { .. })
        ));
    }
}
