use multiaddr::Multiaddr;

use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_crypto::keysecure::types::ToKeySecure;
use prople_crypto::keysecure::KeySecure;

use prople_did_core::did::{query::Params, DID};
use prople_did_core::doc::types::{Doc, ToDoc};
use prople_did_core::hashlink;
use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;

use super::types::{AccountEntityAccessor, AccountError};
use super::URI;

/// `Account` is main entity data structure
///
/// This entity will able to define user/person, organization
/// machine, everything. For the non-human data identity, it should
/// has it's own controller
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "self::serde")]
pub struct Account {
    pub(crate) id: String,
    pub(crate) did: String,
    pub(crate) did_uri: String,
    pub(crate) doc: Doc,
    pub(crate) doc_private_keys: IdentityPrivateKeyPairs,
    pub(crate) keysecure: KeySecure,

    #[serde(with = "ts_seconds")]
    pub(crate) created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    pub(crate) updated_at: DateTime<Utc>,
}

impl Account {
    pub fn new(
        did: String,
        did_uri: String,
        doc: Doc,
        doc_private_keys: IdentityPrivateKeyPairs,
        keysecure: KeySecure,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            did,
            did_uri,
            doc,
            doc_private_keys,
            keysecure,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// `generate` used to generate the `DID` including for all of its components, an identity, a doc
    /// including for the `DID Doc Private Keys`, and then assigned it to the [`Account`] main entity object
    pub fn generate(
        password: String,
        current_addr: Option<Multiaddr>,
    ) -> Result<Account, AccountError> {
        let did = DID::new();
        let mut identity = did
            .identity()
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        let account_keysecure = did
            .account()
            .privkey()
            .to_keysecure(password.clone())
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        let doc = identity
            .build_auth_method()
            .build_assertion_method()
            .to_doc();

        let hl_doc = hashlink::generate_from_json(doc.clone())
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        let doc_private_keys = identity.build_private_keys(password.clone()).map_err(|_| {
            AccountError::GenerateIdentityError("unable to build private keys".to_string())
        })?;

        let mut query_params = Params::default();
        query_params.hl = Some(hl_doc);
        query_params.address = current_addr.map(|addr| addr.to_string());

        let did_uri = URI::build_with_raw(did, Some(query_params))
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        let account = Account::new(
            identity.value(),
            did_uri,
            doc,
            doc_private_keys,
            account_keysecure,
        );

        Ok(account)
    }
}

impl ToJSON for Account {
    fn to_json(&self) -> Result<String, BaseError> {
        let json_str =
            serde_json::to_string(&self).map_err(|err| BaseError::ToJSONError(err.to_string()))?;

        Ok(json_str)
    }
}

impl TryInto<Vec<u8>> for Account {
    type Error = AccountError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let json = serde_json::to_vec(&self)
            .map_err(|err| AccountError::GenerateJSONError(err.to_string()))?;
        Ok(json)
    }
}

impl AccountEntityAccessor for Account {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_did(&self) -> String {
        self.did.to_owned()
    }

    fn get_did_uri(&self) -> String {
        self.did_uri.to_owned()
    }

    fn get_doc(&self) -> Doc {
        self.doc.to_owned()
    }

    fn get_doc_private_keys(&self) -> IdentityPrivateKeyPairs {
        self.doc_private_keys.to_owned()
    }

    fn get_keysecure(&self) -> KeySecure {
        self.keysecure.to_owned()
    }

    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at.to_owned()
    }

    fn get_updated_at(&self) -> DateTime<Utc> {
        self.updated_at.to_owned()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_json_str() {
        let account_builder = Account::generate("password".to_string(), None);
        assert!(!account_builder.is_err());

        let json_str = account_builder.unwrap().to_json();
        assert!(!json_str.is_err());
        assert!(!json_str.unwrap().is_empty())
    }

    #[test]
    fn test_build_json_bytes() {
        let account_builder = Account::generate("password".to_string(), None);
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();
        let json_bytes: Result<Vec<u8>, AccountError> = account.try_into();
        assert!(!json_bytes.is_err());

        let json_str = String::from_utf8(json_bytes.unwrap());
        assert!(!json_str.is_err());
    }

    #[test]
    fn test_generate_account_without_address() {
        let account_builder = Account::generate("password".to_string(), None);
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();
        let check_did_uri_params = URI::has_params(account.clone().did_uri);
        assert!(!check_did_uri_params.is_err());
        assert!(check_did_uri_params.unwrap());

        let (_, uri_params, _) = URI::parse(account.did_uri).unwrap();
        assert!(uri_params.hl.is_some());
        assert!(uri_params.address.is_none())
    }

    #[test]
    fn test_generate_account_with_address() {
        let address = "/ip4/127.0.0.1/tcp/1234".parse::<Multiaddr>().unwrap();

        let account_builder = Account::generate("password".to_string(), Some(address));
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();
        let check_did_uri_params = URI::has_params(account.clone().did_uri);
        assert!(!check_did_uri_params.is_err());
        assert!(check_did_uri_params.unwrap());

        let (_, uri_params, _) = URI::parse(account.did_uri).unwrap();
        assert!(uri_params.hl.is_some());
        assert!(uri_params.address.is_some())
    }
}
