use prople_did_core::verifiable::proof::types::Proofable;
use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::uuid::Uuid;

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json::{self, value::Value};

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_crypto::keysecure::KeySecure;

use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
use prople_did_core::verifiable::objects::VC;

use crate::identity::account::types::AccountEntityAccessor;

use crate::identity::verifiable::proof::builder::Builder as ProofBuilder;
use crate::identity::verifiable::types::VerifiableError;

use super::types::{CredentialEntityAccessor, CredentialError};

/// `Credential` is a main entity used to save to internal persistent storage
/// This data must contain a [`VC`] and [`KeySecure`]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Credential {
    pub(crate) id: String,
    pub(crate) did_issuer: String,
    pub(crate) did_vc: String,
    pub(crate) did_vc_doc_private_keys: IdentityPrivateKeyPairs,
    pub(crate) vc: VC,
    pub(crate) keysecure: KeySecure,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
}

impl Credential {
    pub fn new(
        did_issuer: String,
        did_vc: String,
        did_vc_doc_private_keys: IdentityPrivateKeyPairs,
        vc: VC,
        keysecure: KeySecure,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            keysecure,
            did_issuer,
            did_vc,
            did_vc_doc_private_keys,
            vc,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub async fn generate(
        account: impl AccountEntityAccessor,
        password: String,
        did_issuer: String,
        claims: Value,
    ) -> Result<Credential, CredentialError> {
        if password.is_empty() {
            return Err(CredentialError::CommonError(
                VerifiableError::ValidationError("password was missing".to_string()),
            ));
        }

        if did_issuer.is_empty() {
            return Err(CredentialError::CommonError(
                VerifiableError::ValidationError("did_issuer was missing".to_string()),
            ));
        }

        let account_did = account.get_did();
        let account_keysecure = account.get_keysecure();
        let account_doc_private_key_pairs = account.get_doc_private_keys();

        let mut vc = VC::new(account.get_did(), did_issuer.clone());
        vc.add_context(CONTEXT_VC.to_string())
            .add_context(CONTEXT_VC_V2.to_string())
            .add_type("VerifiableCredential".to_string())
            .set_credential(claims);

        let secured =
            ProofBuilder::build_proof(vc.clone(), password, account_doc_private_key_pairs.clone())
                .map_err(|err| CredentialError::GenerateError(err.to_string()))?;

        vc.setup_proof(secured.unwrap());
        let cred = Credential::new(
            did_issuer,
            account_did,
            account_doc_private_key_pairs,
            vc,
            account_keysecure,
        );

        Ok(cred)
    }
}

impl ToJSON for Credential {
    fn to_json(&self) -> Result<String, BaseError> {
        let json_str =
            serde_json::to_string(&self).map_err(|err| BaseError::ToJSONError(err.to_string()))?;

        Ok(json_str)
    }
}

impl TryInto<Vec<u8>> for Credential {
    type Error = CredentialError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let json = serde_json::to_vec(&self)
            .map_err(|err| CredentialError::GenerateJSONError(err.to_string()))?;
        Ok(json)
    }
}

impl TryFrom<Vec<u8>> for Credential {
    type Error = CredentialError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let credential: Credential = serde_json::from_slice(&value)
            .map_err(|err| CredentialError::UnserializeError(err.to_string()))?;
        Ok(credential)
    }
}

impl CredentialEntityAccessor for Credential {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_did_issuer(&self) -> String {
        self.did_issuer.to_owned()
    }

    fn get_did_vc(&self) -> String {
        self.did_vc.to_owned()
    }

    fn get_vc(&self) -> VC {
        self.vc.to_owned()
    }

    fn get_keysecure(&self) -> KeySecure {
        self.keysecure.to_owned()
    }

    fn get_did_vc_doc_private_keys(&self) -> IdentityPrivateKeyPairs {
        self.did_vc_doc_private_keys.to_owned()
    }

    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at.to_owned()
    }

    fn get_updated_at(&self) -> DateTime<Utc> {
        self.updated_at.to_owned()
    }
}
