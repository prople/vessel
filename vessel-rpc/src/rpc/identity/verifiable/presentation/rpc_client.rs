use multiaddr::Multiaddr;

use rst_common::standard::async_trait::async_trait;

use prople_did_core::verifiable::objects::VP;
use prople_jsonrpc_client::types::Executor;

use prople_vessel_core::identity::verifiable::presentation::types::{
    PresentationError, RpcBuilder,
};

use super::rpc_method::{Method, Vessel as VesselMethod};
use super::rpc_param::{Param, Vessel as VesselParam};
use crate::rpc::shared::rpc::call;
use crate::rpc::shared::rpc::method::build_rpc_method;

#[derive(Clone)]
pub struct RpcClient<TExecutor>
where
    TExecutor: Executor<()>,
{
    client: TExecutor,
}

impl<TExecutor> RpcClient<TExecutor>
where
    TExecutor: Executor<()>,
{
    pub fn new(client: TExecutor) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<TExecutor> RpcBuilder for RpcClient<TExecutor>
where
    TExecutor: Executor<()> + Send + Sync + Clone,
{
    async fn send_to_verifier(
        &self,
        addr: Multiaddr,
        did_verifier: String,
        vp: VP,
    ) -> Result<(), PresentationError> {
        let rpc_param = Param::Vessel(VesselParam::PostPresentation { did_verifier, vp });
        let _ = call(
            self.client.clone(),
            addr,
            build_rpc_method(Method::Vessel(VesselMethod::PostPresentation)),
            Some(rpc_param),
        )
        .await
        .map_err(|err| PresentationError::VerifyError(err.to_string()))?;

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

    use prople_did_core::verifiable::objects::VP;

    use prople_jsonrpc_core::objects::RpcRequest;
    use prople_jsonrpc_core::types::{
        RpcError, RpcErrorBuilder, RpcId, INVALID_PARAMS_CODE, INVALID_PARAMS_MESSAGE,
    };

    use prople_jsonrpc_client::executor::reqwest::Reqwest as ReqwestExecutor;
    use prople_jsonrpc_client::types::{JSONResponse, RpcValue};

    fn generate_rpc_client() -> RpcClient<ReqwestExecutor<()>> {
        return RpcClient::new(ReqwestExecutor::new());
    }

    fn generate_vp() -> VP {
        VP::new()
    }

    fn parse_url(url: String) -> (String, u16) {
        let splitted = url.as_str().split(":").collect::<Vec<&str>>();
        let port_str = splitted[2].parse::<u16>();
        (format!("{}{}", splitted[0], splitted[1]), port_str.unwrap())
    }

    #[tokio::test]
    async fn test_send_to_verifier() {
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let (_, port) = parse_url(base_url);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port));

        let vp = generate_vp();
        let param = Param::Vessel(VesselParam::PostPresentation {
            did_verifier: String::from("did:verifier"),
            vp: vp.clone(),
        });
        let param_value = param.build_serde_value().unwrap();

        let rpc_method = build_rpc_method(Method::Vessel(VesselMethod::PostPresentation));
        let jsonresp: JSONResponse<()> = JSONResponse {
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
            .send_to_verifier(addr, String::from("did:verifier"), vp)
            .await;

        assert!(!resp.is_err());
        mock.assert();
    }

    #[tokio::test]
    async fn test_error_endpoint_send_to_verifier() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]));

        let vp = generate_vp();
        let client = generate_rpc_client();
        let resp = client
            .send_to_verifier(addr, String::from("did-verifier"), vp)
            .await;

        assert!(resp.is_err());
        assert!(matches!(
            resp.unwrap_err(),
            PresentationError::VerifyError(_)
        ))
    }

    #[tokio::test]
    async fn test_error_response_send_to_verifier() {
        let mut server = Server::new_async().await;
        let base_url = server.url();
        let (_, port) = parse_url(base_url);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port));

        let vp = generate_vp();
        let param = Param::Vessel(VesselParam::PostPresentation {
            did_verifier: String::from("did:verifier"),
            vp: vp.clone(),
        });

        let param_value = param.build_serde_value().unwrap();

        let rpc_method = build_rpc_method(Method::Vessel(VesselMethod::PostPresentation));
        let response_err = RpcErrorBuilder::build(RpcError::InvalidParams);
        let jsonresp: JSONResponse<()> = JSONResponse {
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
            .send_to_verifier(addr, String::from("did:verifier"), vp)
            .await;

        assert!(resp.is_err());
        mock.assert();

        let err_msg = resp.unwrap_err();
        match err_msg {
            PresentationError::VerifyError(msg) => {
                assert!(msg.contains(INVALID_PARAMS_MESSAGE));
                assert!(msg.contains(&INVALID_PARAMS_CODE.to_string()));
            }
            _ => panic!("unknown error enum"),
        }
    }
}
