use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::uuid::Uuid;

use prople_crypto::keysecure::types::ToKeySecure;
use prople_crypto::keysecure::KeySecure;

use prople_did_core::did::DID;
use prople_did_core::doc::types::{Doc, ToDoc};
use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;

use super::types::AccountError;

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
        doc: Doc,
        doc_private_keys: IdentityPrivateKeyPairs,
        keysecure: KeySecure,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            did,
            doc,
            doc_private_keys,
            keysecure,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// `generate` used to generate the `DID` including for all of its components, an identity, a doc
    /// including for the `DID Doc Private Keys`, and then assigned it to the [`Account`] main entity object
    pub fn generate(password: String) -> Result<Account, AccountError> {
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

        let doc_private_keys = identity.build_private_keys(password).map_err(|_| {
            AccountError::GenerateIdentityError("unable to build private keys".to_string())
        })?;

        let account = Account::new(identity.value(), doc, doc_private_keys, account_keysecure);
        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tests_generate_account() {
        let account_builder = Account::generate("password".to_string());
        assert!(!account_builder.is_err());
    }
}
