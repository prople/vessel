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

    /// `parse` used to parse given `DID URI` used to parse and generate [`Multiaddr`], [`Params`]
    /// and `DID Account URI`
    pub fn parse(uri: String) -> Result<(Multiaddr, Params, String), AccountError> {
        let (did_uri, uri_params) =
            DID::parse_uri(uri).map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        if uri_params.hl.is_none() {
            return Err(AccountError::ResolveDIDError(
                "invalid hashlink value".to_string(),
            ));
        }

        let parsed_addr = uri_params
            .parse_multiaddr()
            .map_err(|err| AccountError::ResolveDIDError(err.to_string()))?
            .ok_or(AccountError::ResolveDIDError(
                "unable to parse MultiAddress format".to_string(),
            ))?;

        Ok((parsed_addr, uri_params, did_uri))
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
        let account_builder = Account::generate("password".to_string());
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();

        let doc = account.doc.clone();
        let doc_hl_result = generate_from_json(doc);
        assert!(!doc_hl_result.is_err());

        let doc_hl = doc_hl_result.unwrap();
        let params = Params {
            address: Some("test-addr".to_string()),
            hl: Some(doc_hl.clone()),
            service: Some("peer".to_string()),
        };

        let uri = URI::build(account.clone(), "password".to_string(), Some(params));
        assert!(!uri.is_err());

        let value = account.did;
        let uri_expected = format!("{}?service=peer&address=test-addr&hl={}", value, doc_hl);
        assert_eq!(uri.unwrap(), uri_expected)
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
            service: Some("peer".to_string()),
        };

        let uri_builder = URI::build(account.clone(), "password".to_string(), Some(params));
        assert!(!uri_builder.is_err());

        let uri = uri_builder.unwrap();
        let uri_resolver = URI::parse(uri);
        assert!(!uri_resolver.is_err());

        let uri_objects = uri_resolver.unwrap();
        assert_eq!(uri_objects.0, input_addr);
        assert_eq!(uri_objects.2, account.did);
    }
}
