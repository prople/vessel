use multiaddr::Multiaddr;

use rst_common::standard::async_trait::async_trait;

use prople_did_core::verifiable::objects::VC;
use prople_jsonrpc_client::types::Executor;

use prople_vessel_core::identity::verifiable::credential::types::{CredentialError, RpcBuilder};

use crate::rpc::shared::rpc::method::build_rpc_method;
use crate::rpc::shared::rpc::{call, CallError};

use super::rpc_method::{Method, Vessel as VesselMethod};
use super::rpc_param::{Param, Vessel as VesselParam};

#[derive(Clone)]
pub struct RpcClient<TExecutor>
where
    TExecutor: Executor<(), ErrorData = CredentialError>,
{
    client: TExecutor,
}

impl<TExecutor> RpcClient<TExecutor>
where
    TExecutor: Executor<(), ErrorData = CredentialError>,
{
    pub fn new(client: TExecutor) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<TExecutor> RpcBuilder for RpcClient<TExecutor>
where
    TExecutor: Executor<(), ErrorData = CredentialError> + Send + Sync + Clone,
{
    async fn send_credential_to_holder(
        &self,
        did_holder: String,
        addr: Multiaddr,
        vc: VC,
    ) -> Result<(), CredentialError> {
        let rpc_param = Param::Vessel(VesselParam::PostCredential { did_holder, vc });
        let _ = call(
            self.client.clone(),
            addr,
            build_rpc_method(Method::Vessel(VesselMethod::PostCredential)),
            Some(rpc_param),
        )
        .await
        .map_err(|err| match err {
            CallError::EndpointError(e) => CredentialError::InvalidMultiAddr(e.to_string()),
            CallError::ExecutorError(e) => CredentialError::SendError(e.to_string()),
            CallError::ResponseError(e) => CredentialError::SendError(e.to_string()),
        })?;

        Ok(())
    }

    async fn verify_credential_to_issuer(
        &self,
        addr: Multiaddr,
        vc: VC,
    ) -> Result<(), CredentialError> {
        let rpc_param = Param::Vessel(VesselParam::VerifyCredential { vc });
        let _ = call(
            self.client.clone(),
            addr,
            build_rpc_method(Method::Vessel(VesselMethod::VerifyCredential)),
            Some(rpc_param),
        )
        .await
        .map_err(|err| match err {
            CallError::EndpointError(e) => CredentialError::InvalidMultiAddr(e.to_string()),
            CallError::ExecutorError(e) => CredentialError::SendError(e.to_string()),
            CallError::ResponseError(e) => CredentialError::SendError(e.to_string()),
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};
    use multiaddr::multiaddr;

    use rst_common::standard::serde_json;
    use rst_common::with_tokio::tokio;

    use prople_did_core::verifiable::objects::VC;

    use prople_jsonrpc_core::objects::RpcRequest;
    use prople_jsonrpc_core::types::{
        RpcError, RpcErrorBuilder, RpcId, INVALID_PARAMS_CODE, INVALID_PARAMS_MESSAGE,
    };

    use prople_jsonrpc_client::executor::reqwest::Reqwest as ReqwestExecutor;
    use prople_jsonrpc_client::types::{JSONResponse, RpcValue};

    fn generate_rpc_client() -> RpcClient<ReqwestExecutor<(), CredentialError>> {
        return RpcClient::new(ReqwestExecutor::new());
    }

    fn generate_vc(id: String, issuer: String) -> VC {
        VC::new(id, issuer)
    }

    fn parse_url(url: String) -> (String, u16) {
        let splitted = url.as_str().split(":").collect::<Vec<&str>>();
        let port_str = splitted[2].parse::<u16>();
        (format!("{}{}", splitted[0], splitted[1]), port_str.unwrap())
    }

    #[tokio::test]
    async fn test_send_credential_to_holder() {
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let (_, port) = parse_url(base_url);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port));

        let vc = generate_vc(String::from("id"), String::from("issuer"));
        let param = Param::Vessel(VesselParam::PostCredential {
            did_holder: String::from("did-holder"),
            vc: vc.clone(),
        });
        let param_value = param.build_serde_value().unwrap();

        let rpc_method = build_rpc_method(Method::Vessel(VesselMethod::PostCredential));
        let jsonresp: JSONResponse<(), CredentialError> = JSONResponse {
            id: Some(RpcId::IntegerVal(1)),
            result: None,
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
        let resp = client
            .send_credential_to_holder(String::from("did-holder"), addr, vc)
            .await;

        assert!(!resp.is_err());
        mock.assert();
    }

    #[tokio::test]
    async fn test_verify_credential_to_issuer() {
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let (_, port) = parse_url(base_url);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port));

        let vc = generate_vc(String::from("id"), String::from("issuer"));
        let param = Param::Vessel(VesselParam::VerifyCredential { vc: vc.clone() });
        let param_value = param.build_serde_value().unwrap();

        let rpc_method = build_rpc_method(Method::Vessel(VesselMethod::VerifyCredential));
        let jsonresp: JSONResponse<(), CredentialError> = JSONResponse {
            id: Some(RpcId::IntegerVal(1)),
            result: None,
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
        let resp = client.verify_credential_to_issuer(addr, vc).await;

        assert!(!resp.is_err());
        mock.assert();
    }

    #[tokio::test]
    async fn test_error_endpoint_send_credential_to_holder() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]));

        let vc = generate_vc(String::from("id"), String::from("issuer"));
        let client = generate_rpc_client();
        let resp = client
            .send_credential_to_holder(String::from("did-holder"), addr, vc)
            .await;

        assert!(resp.is_err());
        assert!(matches!(
            resp.unwrap_err(),
            CredentialError::InvalidMultiAddr(_)
        ))
    }

    #[tokio::test]
    async fn test_error_endpoint_verify_credential_to_issuer() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]));

        let vc = generate_vc(String::from("id"), String::from("issuer"));
        let client = generate_rpc_client();
        let resp = client.verify_credential_to_issuer(addr, vc).await;

        assert!(resp.is_err());
        assert!(matches!(
            resp.unwrap_err(),
            CredentialError::InvalidMultiAddr(_)
        ))
    }

    #[tokio::test]
    async fn test_error_response_send_credential_to_holder() {
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let (_, port) = parse_url(base_url);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port));

        let vc = generate_vc(String::from("did-holder"), String::from("issuer"));
        let param = Param::Vessel(VesselParam::PostCredential {
            did_holder: String::from("did-holder"),
            vc: vc.clone(),
        });

        let param_value = param.build_serde_value().unwrap();

        let rpc_method = build_rpc_method(Method::Vessel(VesselMethod::PostCredential));
        let response_err = RpcErrorBuilder::<CredentialError>::build(RpcError::InvalidParams, None);
        let jsonresp: JSONResponse<(), CredentialError> = JSONResponse {
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
        let resp = client
            .send_credential_to_holder(String::from("did-holder"), addr, vc)
            .await;

        assert!(resp.is_err());
        mock.assert();

        let err_msg = resp.unwrap_err();
        match err_msg {
            CredentialError::SendError(msg) => {
                assert!(msg.contains(INVALID_PARAMS_MESSAGE));
                assert!(msg.contains(&INVALID_PARAMS_CODE.to_string()));
            }
            _ => panic!("unknown error enum"),
        }
    }

    #[tokio::test]
    async fn test_error_response_verify_credential_to_issuer() {
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let (_, port) = parse_url(base_url);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port));

        let vc = generate_vc(String::from("did-holder"), String::from("issuer"));
        let param = Param::Vessel(VesselParam::VerifyCredential { vc: vc.clone() });

        let param_value = param.build_serde_value().unwrap();

        let rpc_method = build_rpc_method(Method::Vessel(VesselMethod::VerifyCredential));
        let response_err = RpcErrorBuilder::<CredentialError>::build(RpcError::InvalidParams, None);
        let jsonresp: JSONResponse<(), CredentialError> = JSONResponse {
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
        let resp = client.verify_credential_to_issuer(addr, vc).await;

        assert!(resp.is_err());
        mock.assert();

        let err_msg = resp.unwrap_err();
        match err_msg {
            CredentialError::SendError(msg) => {
                assert!(msg.contains(INVALID_PARAMS_MESSAGE));
                assert!(msg.contains(&INVALID_PARAMS_CODE.to_string()));
            }
            _ => panic!("unknown error enum"),
        }
    }
}
