use std::borrow::Cow;
use std::fmt::Debug;

use http::Uri;
use multiaddr::{multiaddr, Multiaddr, Protocol};

use rst_common::standard::serde::de::DeserializeOwned;

use prople_jsonrpc_client::executor::reqwest::Reqwest;
use prople_jsonrpc_client::types::Executor;

use crate::types::CliError;

pub fn build_client<TResp>() -> impl Executor<TResp>
where
    TResp: DeserializeOwned + Clone + Send + Sync + Debug,
{
    Reqwest::<TResp>::new()
}

pub fn http_to_multiaddr(http_addr: String) -> Result<Multiaddr, CliError> {
    let parsed = http_addr
        .parse::<Uri>()
        .map_err(|err| CliError::RpcError(err.to_string()))?;

    match parsed.host() {
        Some(host) => {
            let mut maddr = multiaddr!(Dns4(Cow::from(host)));

            let scheme = {
                match parsed.scheme_str() {
                    Some("http") => Protocol::Http,
                    Some("https") => Protocol::Https,
                    _ => return Err(CliError::RpcError(String::from("missing http scheme"))),
                }
            };

            maddr.push(scheme);

            if parsed.port().is_some() {
                let port = parsed.port().unwrap();
                maddr.push(Protocol::Tcp(port.as_u16()));
            }

            Ok(maddr)
        }
        None => Err(CliError::RpcError(String::from("missing host"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_http_address() {
        let maddr = http_to_multiaddr(String::from("invalid uri"));
        assert!(maddr.is_err());
        assert!(matches!(maddr.unwrap_err(), CliError::RpcError(_)))
    }

    #[test]
    fn test_invalid_http_address_no_scheme() {
        let maddr = http_to_multiaddr(String::from("google.com"));
        assert!(maddr.is_err());
        assert!(matches!(maddr.unwrap_err(), CliError::RpcError(_)))
    }

    #[test]
    fn test_valid_http_address() {
        let maddr = http_to_multiaddr(String::from("http://google.com"));
        assert!(!maddr.is_err());

        let addr = maddr.unwrap();
        let maddr_comps = addr.iter().collect::<Vec<_>>();
        assert_eq!(maddr_comps.len(), 2);
        assert_eq!(maddr_comps[0], Protocol::Dns4(Cow::from("google.com")));
        assert_eq!(maddr_comps[1], Protocol::Http)
    }

    #[test]
    fn test_valid_https_address() {
        let maddr = http_to_multiaddr(String::from("https://google.com"));
        assert!(!maddr.is_err());

        let addr = maddr.unwrap();
        let maddr_comps = addr.iter().collect::<Vec<_>>();
        assert_eq!(maddr_comps.len(), 2);
        assert_eq!(maddr_comps[0], Protocol::Dns4(Cow::from("google.com")));
        assert_eq!(maddr_comps[1], Protocol::Https)
    }

    #[test]
    fn test_valid_host_port() {
        let maddr = http_to_multiaddr(String::from("http://localhost:8282"));
        assert!(!maddr.is_err());

        let addr = maddr.unwrap();
        let maddr_comps = addr.iter().collect::<Vec<_>>();
        assert_eq!(maddr_comps.len(), 3);
        assert_eq!(maddr_comps[0], Protocol::Dns4(Cow::from("localhost")));
        assert_eq!(maddr_comps[1], Protocol::Http);
        assert_eq!(maddr_comps[2], Protocol::Tcp(8282u16))
    }
}
