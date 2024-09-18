use prople_jsonrpc_core::types::RpcMethod;

use crate::rpc::shared::rpc::method::RpcMethodBuilder;
use crate::rpc::shared::types::CommonError;

const METHOD_GENERATE_DID: &str = "identity.did.generate_did";
const METHOD_BUILD_DID_URI: &str = "identity.did.build_did_uri";
const METHOD_RESOLVE_DID_URI: &str = "identity.did.resolve_did_uri";
const METHOD_RESOLVE_DID_DOC: &str = "identity.did.resolve_did_doc";
const METHOD_REMOVE_DID: &str = "identity.did.remove_did";
const METHOD_GET_ACCOUNT_DID: &str = "identity.did.get_account_did";

#[derive(Clone, Debug, PartialEq)]
pub enum Method {
    GenerateDID,
    BuildDIDURI,
    ResolveDIDURI,
    ResolveDIDDoc,
    RemoveDID,
    GetAccountDID,
}

impl RpcMethodBuilder for Method {
    fn build_path(&self) -> &str {
        match self {
            Method::GenerateDID => METHOD_GENERATE_DID,
            Method::BuildDIDURI => METHOD_BUILD_DID_URI,
            Method::ResolveDIDURI => METHOD_RESOLVE_DID_URI,
            Method::ResolveDIDDoc => METHOD_RESOLVE_DID_DOC,
            Method::RemoveDID => METHOD_REMOVE_DID,
            Method::GetAccountDID => METHOD_GET_ACCOUNT_DID,
        }
    }
}

impl TryFrom<RpcMethod> for Method {
    type Error = CommonError;

    fn try_from(value: RpcMethod) -> Result<Self, Self::Error> {
        let given = value.to_string();
        match given.as_str() {
            _ if given.as_str().contains(METHOD_GENERATE_DID) => Ok(Self::GenerateDID),
            _ if given.as_str().contains(METHOD_BUILD_DID_URI) => Ok(Self::BuildDIDURI),
            _ if given.as_str().contains(METHOD_RESOLVE_DID_URI) => Ok(Self::ResolveDIDURI),
            _ if given.as_str().contains(METHOD_RESOLVE_DID_DOC) => Ok(Self::ResolveDIDDoc),
            _ if given.as_str().contains(METHOD_REMOVE_DID) => Ok(Self::RemoveDID),
            _ if given.as_str().contains(METHOD_GET_ACCOUNT_DID) => Ok(Self::GetAccountDID),
            _ => Err(CommonError::MethodError(format!(
                "unknown method: {}",
                given.to_string()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use table_test::table_test;

    use prople_jsonrpc_core::types::RpcMethod;

    use crate::rpc::shared::rpc::method::build_rpc_method;

    #[test]
    fn test_from_rpc_method() {
        let table = vec![
            (build_rpc_method(Method::GenerateDID), Method::GenerateDID),
            (build_rpc_method(Method::BuildDIDURI), Method::BuildDIDURI),
            (
                build_rpc_method(Method::ResolveDIDURI),
                Method::ResolveDIDURI,
            ),
            (
                build_rpc_method(Method::ResolveDIDDoc),
                Method::ResolveDIDDoc,
            ),
            (build_rpc_method(Method::RemoveDID), Method::RemoveDID),
            (
                build_rpc_method(Method::GetAccountDID),
                Method::GetAccountDID,
            ),
        ];

        for (validator, input, expected) in table_test!(table) {
            let from_method = Method::try_from(input.clone());
            assert!(!from_method.is_err());

            validator
                .given(&format!("{:?}", input))
                .when("cast back")
                .then("back to original form")
                .assert_eq(expected, from_method.unwrap());
        }
    }

    #[test]
    fn test_from_rpc_method_error() {
        let rpc_method = RpcMethod::from("unknown.method");
        let from_method = Method::try_from(rpc_method);
        assert!(from_method.is_err());
        assert!(matches!(
            from_method.unwrap_err(),
            CommonError::MethodError(_)
        ))
    }
}
