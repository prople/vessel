use multiaddr::Multiaddr;

use prople_did_core::did::{query::Params, DID};

use super::types::{AccountEntityAccessor, AccountError};

/// `URI` is a domain service that build specifically
/// for the `DID URI` management, it should be used to [`URI::build`] and [`URI::parse`]
pub struct URI;

impl URI {
    /// `build` used to build the `DID URI` based on given [`Account`] and query params
    pub fn build(
        account: impl AccountEntityAccessor,
        password: String,
        params: Option<Params>,
    ) -> Result<String, AccountError> {
        let did = DID::from_keysecure(password, account.get_keysecure())
            .map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        did.build_uri(params)
            .map_err(|err| AccountError::BuildURIError(err.to_string()))
    }

    /// `build_with_raw` is almost like [`URI::build`] but with difference this method doesn't need
    /// an account entity. The main parameters are just the [`DID`] and query params
    pub fn build_with_raw(did: DID, params: Option<Params>) -> Result<String, AccountError> {
        did.build_uri(params)
            .map_err(|err| AccountError::BuildURIError(err.to_string()))
    }

    /// `parse` used to parse given `DID URI` used to parse and generate [`Multiaddr`], [`Params`]
    /// and `DID Account URI`
    pub fn parse(uri: String) -> Result<(Option<Multiaddr>, Params, String), AccountError> {
        let (did_uri, uri_params) =
            DID::parse_uri(uri).map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        let parsed_addr = uri_params
            .parse_multiaddr()
            .map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        Ok((parsed_addr, uri_params, did_uri))
    }

    pub fn has_params(uri: String) -> Result<bool, AccountError> {
        let (_, uri_params, _) = URI::parse(uri)?;
        let has_params = uri_params.address.is_some() || uri_params.hl.is_some();
        Ok(has_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use multiaddr::multiaddr;
    use prople_did_core::hashlink::generate_from_json;

    use crate::identity::account::Account;

    #[test]
    fn test_build_uri() {
        let address = "/ip4/127.0.0.1/tcp/1234".parse::<Multiaddr>().unwrap();
        let account_builder = Account::generate("password".to_string());
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();

        let doc = account.doc.clone();
        let doc_hl_result = generate_from_json(doc);
        assert!(!doc_hl_result.is_err());

        let doc_hl = doc_hl_result.unwrap();
        let params = Params {
            address: Some(address.to_string()),
            hl: Some(doc_hl.clone()),
        };

        let uri = URI::build(account.clone(), "password".to_string(), Some(params));
        assert!(!uri.is_err());

        let value = account.did;
        let uri_expected = format!("{}?address={}&hl={}", value, address.to_string(), doc_hl);
        assert_eq!(uri.unwrap(), uri_expected)
    }

    #[test]
    fn test_build_uri_with_raw() {
        let address = "/ip4/127.0.0.1/tcp/1234".parse::<Multiaddr>().unwrap();
        let did = DID::new();

        let mut query_params = Params::default();
        query_params.address = Some(address.to_string());

        let uri = URI::build_with_raw(did.clone(), Some(query_params));
        assert!(!uri.is_err());

        let did_uri = uri.unwrap();
        let did_uri_expected = format!(
            "{}?address={}",
            did.identity().unwrap().value(),
            address.to_string()
        );
        assert_eq!(did_uri_expected, did_uri)
    }

    #[test]
    fn test_did_uri_has_params() {
        let address = "/ip4/127.0.0.1/tcp/1234".parse::<Multiaddr>().unwrap();
        let did = DID::new();

        let mut query_params = Params::default();
        query_params.address = Some(address.to_string());

        let uri = URI::build_with_raw(did.clone(), Some(query_params));
        assert!(!uri.is_err());

        let did_uri = uri.unwrap();
        let check_has_params = URI::has_params(did_uri);
        assert!(!check_has_params.is_err());
        assert!(check_has_params.unwrap());
    }

    #[test]
    fn test_build_uri_invalid_password() {
        let account_builder = Account::generate("password".to_string());
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();

        let uri = URI::build(account, "invalid_password".to_string(), None);
        assert!(uri.is_err());
    }

    #[test]
    fn test_parse_uri() {
        let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));

        let account_builder = Account::generate("password".to_string());
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();

        let doc = account.doc.clone();
        let doc_hl_result = generate_from_json(doc);
        assert!(!doc_hl_result.is_err());

        let doc_hl = doc_hl_result.unwrap();
        let params = Params {
            address: Some(input_addr.to_string()),
            hl: Some(doc_hl.clone()),
        };

        let uri_builder = URI::build(account.clone(), "password".to_string(), Some(params));
        assert!(!uri_builder.is_err());

        let uri_resolver = URI::parse(uri_builder.unwrap());
        assert!(!uri_resolver.is_err());

        let uri_objects = uri_resolver.unwrap();
        assert_eq!(uri_objects.0.unwrap(), input_addr);
        assert!(!uri_objects.2.contains("&"));
        assert!(!uri_objects.2.contains("address"));
        assert!(!uri_objects.2.contains("hl"));
    }
}
