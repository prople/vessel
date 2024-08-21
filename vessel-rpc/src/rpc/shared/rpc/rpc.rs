use multiaddr::{Multiaddr, Protocol};

use rst_common::with_errors::thiserror::{self, Error};

#[derive(Debug, Error)]
pub enum EndpointError {
    #[error("rpc error: invalid addr: {0}")]
    InvalidMultiAddr(String),

    #[error("rpc error: empty addr")]
    EmptyMultiAddr,
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

    let endpoint = format!("{}:{}", host, port);
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
        println!("{}", parsed.unwrap_err())
    }

    #[test]
    fn test_multiaddr_dns() {
        let addr = multiaddr!(Dns("http://google.com"), Tcp(8080u16));
        let parsed = build_endpoint(addr);
        assert!(!parsed.is_err());
        assert_eq!("http://google.com:8080", parsed.unwrap())
    }

    #[test]
    fn test_multiaddr_dns4() {
        let addr = multiaddr!(Dns4("http://google.com"), Tcp(8080u16));
        let parsed = build_endpoint(addr);
        assert!(!parsed.is_err());
        assert_eq!("http://google.com:8080", parsed.unwrap())
    }

    #[test]
    fn test_multiaddr_ip4() {
        let addr = multiaddr!(Ip4(Ipv4Addr::new(127, 0, 0, 1)), Tcp(8080u16));
        let parsed = build_endpoint(addr);
        assert!(!parsed.is_err());
        assert_eq!("http://127.0.0.1:8080", parsed.unwrap())
    }
}
