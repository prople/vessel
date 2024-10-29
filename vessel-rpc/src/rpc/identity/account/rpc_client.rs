use multiaddr::Multiaddr;

use rst_common::standard::async_trait::async_trait;

use prople_did_core::doc::types::Doc;

use prople_jsonrpc_client::types::Executor;

use prople_vessel_core::identity::account::types::AccountError;
use prople_vessel_core::identity::account::types::RpcBuilder;

use crate::rpc::shared::rpc::method::build_rpc_method;
use crate::rpc::shared::rpc::{call, CallError};

use super::rpc_method::Method;
use super::rpc_param::{Domain, Param};

#[derive(Clone)]
pub struct RpcClient<TExecutor>
where
    TExecutor: Executor<Doc> + Clone,
{
    client: TExecutor,
}

impl<TExecutor> RpcClient<TExecutor>
where
    TExecutor: Executor<Doc> + Clone,
{
    pub fn new(client: TExecutor) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<TExecutor> RpcBuilder for RpcClient<TExecutor>
where
    TExecutor: Executor<Doc> + Send + Sync + Clone,
{
    async fn resolve_did_doc(&self, addr: Multiaddr, did: String) -> Result<Doc, AccountError> {
        let rpc_param = Param::Domain(Domain::ResolveDIDDoc { did });
        let rpc_response = call(
            self.client.clone(),
            addr,
            build_rpc_method(Method::ResolveDIDDoc),
            Some(rpc_param),
        )
        .await
        .map_err(|err| match err {
            CallError::EndpointError(e) => AccountError::InvalidMultiAddr(e.to_string()),
            CallError::ExecutorError(e) => AccountError::ResolveDIDError(e.to_string()),
            CallError::ResponseError(e) => AccountError::ResolveDIDError(e.to_string()),
        })?;

        match rpc_response.result {
            Some(doc) => Ok(doc),
            None => Err(AccountError::ResolveDIDError(String::from(
                "missing DID Doc",
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};
    use multiaddr::multiaddr;

    use rst_common::standard::serde_json;
    use rst_common::with_tokio::tokio;

    use prople_did_core::did::DID;
    use prople_did_core::doc::types::ToDoc;

    use prople_jsonrpc_core::objects::RpcRequest;
    use prople_jsonrpc_core::types::{
        RpcError, RpcErrorBuilder, RpcId, INVALID_PARAMS_CODE, INVALID_PARAMS_MESSAGE,
    };

    use prople_jsonrpc_client::executor::reqwest::Reqwest as ReqwestExecutor;
    use prople_jsonrpc_client::types::{JSONResponse, RpcValue};

    fn generate_rpc_client() -> RpcClient<ReqwestExecutor<Doc>> {
        return RpcClient::new(ReqwestExecutor::new());
    }

    fn generate_doc() -> (Doc, DID) {
        let did = DID::new();
        let identity = did.identity().unwrap();

        return (identity.to_doc(), did);
    }

    fn parse_url(url: String) -> (String, u16) {
        let splitted = url.as_str().split(":").collect::<Vec<&str>>();
        let port_str = splitted[2].parse::<u16>();
        (format!("{}{}", splitted[0], splitted[1]), port_str.unwrap())
    }

    #[tokio::test]
    async fn test_resolve_did_doc_success() {
        let (doc, did) = generate_doc();

        let did_str = did.identity().unwrap().value();
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let (_, port) = parse_url(base_url);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port));

        let param = Param::Domain(Domain::ResolveDIDDoc {
            did: did_str.clone(),
        });

        let param_value = param.build_serde_value().unwrap();

        let rpc_method = build_rpc_method(Method::ResolveDIDDoc);
        let jsonresp: JSONResponse<Doc> = JSONResponse {
            id: Some(RpcId::IntegerVal(1)),
            result: Some(doc),
            error: None,
            jsonrpc: String::from("2.0"),
        };

        let jsonresp_str_builder = serde_json::to_string(&jsonresp).unwrap();

        let request_payload = RpcRequest {
            jsonrpc: String::from("2.0"),
            method: rpc_method.to_string(),
            params: Some(param_value),
            id: None,
        };

        let request_payload_value = serde_json::to_value(request_payload).unwrap();

        let mock = server
            .mock("POST", "/rpc")
            .match_body(Matcher::Json(request_payload_value))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(jsonresp_str_builder)
            .create_async()
            .await;

        let client = generate_rpc_client();
        let resp = client.resolve_did_doc(addr, did_str).await;

        assert!(!resp.is_err());
        mock.assert();
    }

    #[tokio::test]
    async fn test_error_endpoint() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]));

        let client = generate_rpc_client();
        let resp = client
            .resolve_did_doc(addr, "did:prople:anything".to_string())
            .await;

        assert!(resp.is_err());
        assert!(matches!(
            resp.unwrap_err(),
            AccountError::InvalidMultiAddr(_)
        ))
    }

    #[tokio::test]
    async fn test_error_response() {
        let (_, did) = generate_doc();

        let did_str = did.identity().unwrap().value();
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let (_, port) = parse_url(base_url);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port));

        let param = Param::Domain(Domain::ResolveDIDDoc {
            did: did_str.clone(),
        });

        let param_value = param.build_serde_value().unwrap();

        let rpc_method = build_rpc_method(Method::ResolveDIDDoc);
        let response_err = RpcErrorBuilder::build(RpcError::InvalidParams);
        let jsonresp: JSONResponse<Doc> = JSONResponse {
            id: Some(RpcId::IntegerVal(1)),
            result: None,
            error: Some(response_err),
            jsonrpc: String::from("2.0"),
        };

        let jsonresp_str_builder = serde_json::to_string(&jsonresp).unwrap();

        let request_payload = RpcRequest {
            jsonrpc: String::from("2.0"),
            method: rpc_method.to_string(),
            params: Some(param_value),
            id: None,
        };

        let request_payload_value = serde_json::to_value(request_payload).unwrap();

        let mock = server
            .mock("POST", "/rpc")
            .match_body(Matcher::Json(request_payload_value))
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(jsonresp_str_builder)
            .create_async()
            .await;

        let client = generate_rpc_client();
        let resp = client.resolve_did_doc(addr, did_str).await;

        assert!(resp.is_err());
        mock.assert();

        let err_msg = resp.unwrap_err();
        match err_msg {
            AccountError::ResolveDIDError(msg) => {
                assert!(msg.contains(INVALID_PARAMS_MESSAGE));
                assert!(msg.contains(&INVALID_PARAMS_CODE.to_string()));
            }
            _ => panic!("unknown error enum"),
        }
    }
}
