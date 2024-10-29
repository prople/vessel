use multiaddr::{Multiaddr, Protocol};

use rst_common::{
    standard::serde::de::DeserializeOwned,
    with_errors::thiserror::{self, Error},
};

use prople_jsonrpc_client::types::{Executor, ExecutorError, JSONResponse, RpcValue};
use prople_jsonrpc_core::types::RpcMethod;

const RPC_PATH: &str = "/rpc";

#[derive(Debug, Error)]
pub enum EndpointError {
    #[error("rpc error: invalid addr: {0}")]
    InvalidMultiAddr(String),

    #[error("rpc error: empty addr")]
    EmptyMultiAddr,
}

#[derive(Debug, Error)]
pub enum CallError {
    #[error("endpoint error: {0}")]
    EndpointError(#[from] EndpointError),

    #[error("executor error: {0}")]
    ExecutorError(#[from] ExecutorError),

    #[error("response error: {0}")]
    ResponseError(String),
}

pub async fn call<T, TExec>(
    client: TExec,
    addr: Multiaddr,
    method: RpcMethod,
    param: Option<impl RpcValue>,
) -> Result<JSONResponse<T>, CallError>
where
    T: Clone + Send + Sync + DeserializeOwned,
    TExec: Executor<T>,
{
    let endpoint = build_endpoint(addr).map_err(|err| CallError::EndpointError(err))?;

    let rpc_method = method.to_string();
    let rpc_response = client
        .call(endpoint, param, rpc_method, None)
        .await
        .map_err(|err| CallError::ExecutorError(err))?;

    if rpc_response.error.is_some() {
        let json_err = rpc_response.error.map_or(
            CallError::ResponseError(String::from("missing response error")),
            |val| {
                CallError::ResponseError(format!("code: {} | message: {}", val.code, val.message))
            },
        );

        return Err(json_err);
    }

    Ok(rpc_response)
}

/// build_endpoint used to parse given [`Multiaddr`] object into supported endpoint url
/// The parsed endpoint will only accept three protocols which are:
///
/// - [`Protocol::Ip4`]
/// - [`Protocol::Dns`]
/// - [`Protocol::Dns4`]
///
/// Any other protocols will be treat as an error
pub fn build_endpoint(addr: Multiaddr) -> Result<String, EndpointError> {
    if addr.is_empty() {
        return Err(EndpointError::EmptyMultiAddr);
    }

    let addr_cloned = addr.clone();
    let components = addr_cloned.iter().collect::<Vec<_>>();
    if components.len() < 2 {
        return Err(EndpointError::InvalidMultiAddr(
            "invalid multiaddress format".to_string(),
        ));
    }

    let mut endpoint = String::new();
    for comp in components {
        match comp {
            Protocol::Ip4(ip) => endpoint.push_str(format!("http://{}", ip.to_string()).as_str()),
            Protocol::Dns(dns) => endpoint.push_str(dns.to_string().as_str()),
            Protocol::Dns4(dns4) => endpoint.push_str(dns4.to_string().as_str()),
            Protocol::Tcp(port) => endpoint.push_str(format!(":{}", port).as_str()),
            Protocol::Http => endpoint.insert_str(0, "http://"),
            Protocol::Https => endpoint.insert_str(0, "https://"),
            _ => {
                return Err(EndpointError::InvalidMultiAddr(
                    "unknown multiaddrss format".to_string(),
                ))
            }
        }
    }

    endpoint.push_str(RPC_PATH);
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use multiaddr::multiaddr;

    #[test]
    fn test_multiaddr_dns() {
        let addr = multiaddr!(Dns("google.com"), Http, Tcp(8080u16));
        let parsed = build_endpoint(addr);
        assert!(!parsed.is_err());
        assert_eq!("http://google.com:8080/rpc", parsed.unwrap())
    }

    #[test]
    fn test_multiaddr_dns4() {
        let addr = multiaddr!(Dns4("google.com"), Http, Tcp(8080u16));
        let parsed = build_endpoint(addr);
        assert!(!parsed.is_err());
        assert_eq!("http://google.com:8080/rpc", parsed.unwrap())
    }

    #[test]
    fn test_multiaddr_ip4() {
        let addr = multiaddr!(Ip4(Ipv4Addr::new(127, 0, 0, 1)), Tcp(8080u16));
        let parsed = build_endpoint(addr);
        assert!(!parsed.is_err());
        assert_eq!("http://127.0.0.1:8080/rpc", parsed.unwrap())
    }
}
