use multiaddr::{Multiaddr, Protocol};

use rst_common::{
    standard::serde::de::DeserializeOwned,
    with_errors::thiserror::{self, Error},
};

use prople_jsonrpc_client::types::{Executor, ExecutorError, JSONResponse};

const RPC_PATH: &str = "/rpc";

use super::types::{RpcMethod, RpcParam};

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

pub async fn call<T, E, TExec>(
    client: TExec,
    addr: Multiaddr,
    method: RpcMethod,
    param: RpcParam,
) -> Result<JSONResponse<T, E>, CallError>
where
    T: Clone + Send + Sync + DeserializeOwned,
    E: Clone,
    TExec: Executor<T, ErrorData = E>,
{
    let endpoint = build_endpoint(addr).map_err(|err| CallError::EndpointError(err))?;

    let rpc_method = method.build_path().path();
    let rpc_response = client
        .call(endpoint, param, rpc_method, None)
        .await
        .map_err(|err| CallError::ExecutorError(err))?;

    if rpc_response.is_error() {
        let json_err = rpc_response
            .extract_err()
            .map(|val| format!("code: {} | message: {}", val.code, val.message))
            .map_err(|err| CallError::ExecutorError(err))?;

        return Err(CallError::ResponseError(json_err));
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
        return Err(EndpointError::InvalidMultiAddr(String::from(
            "multiaddr length not valid",
        )));
    }

    let host = {
        match &components[0] {
            Protocol::Ip4(ip) => Ok(format!("http://{}", ip.to_string())),
            Protocol::Dns(dns) => Ok(dns.to_string()),
            Protocol::Dns4(dns4) => Ok(dns4.to_string()),
            protocol => Err(EndpointError::InvalidMultiAddr(format!(
                "unknown protocol: {}",
                protocol.to_string()
            ))),
        }
    }?;

    let port = {
        match components[1] {
            Protocol::Tcp(port) => port,
            _ => 80,
        }
    };

    let endpoint = format!("{}:{}{}", host, port, RPC_PATH);
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use multiaddr::multiaddr;

    #[test]
    fn test_multiaddr_invalid() {
        let addr = multiaddr!(Udp(10500u16), QuicV1);
        let parsed = build_endpoint(addr);
        assert!(parsed.is_err());
    }

    #[test]
    fn test_multiaddr_dns() {
        let addr = multiaddr!(Dns("http://google.com"), Tcp(8080u16));
        let parsed = build_endpoint(addr);
        assert!(!parsed.is_err());
        assert_eq!("http://google.com:8080/rpc", parsed.unwrap())
    }

    #[test]
    fn test_multiaddr_dns4() {
        let addr = multiaddr!(Dns4("http://google.com"), Tcp(8080u16));
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
