use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::uuid::Uuid;

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json::value::Value;

use prople_crypto::keysecure::KeySecure;

use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
use prople_did_core::verifiable::objects::VC;

use crate::identity::account::types::AccountEntityAccessor;

use crate::identity::verifiable::proof::builder::Builder as ProofBuilder;
use crate::identity::verifiable::proof::types::Params as ProofParams;
use crate::identity::verifiable::types::VerifiableError;

use super::types::{CredentialEntityAccessor, CredentialError};

/// `Credential` is a main entity used to save to internal persistent storage
/// This data must contain a [`VC`] and [`KeySecure`]
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Credential {
    pub(crate) id: String,
    pub(crate) did: String,
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
        did: String,
        did_vc: String,
        did_vc_doc_private_keys: IdentityPrivateKeyPairs,
        vc: VC,
        keysecure: KeySecure,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            keysecure,
            did,
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
        proof_params: Option<ProofParams>,
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

        let mut vc = VC::new(account.get_did().clone(), did_issuer.clone());
        vc.add_context(CONTEXT_VC.to_string())
            .add_context(CONTEXT_VC_V2.to_string())
            .add_type("VerifiableCredential".to_string())
            .set_credential(claims);

        let proof_builder = ProofBuilder::build_proof(
            vc.clone(),
            password,
            account_doc_private_key_pairs.clone(),
            proof_params,
        )
        .map_err(|err| CredentialError::GenerateError(err.to_string()))?;

        if let Some(proof) = proof_builder {
            vc.proof(proof);
        }

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

impl CredentialEntityAccessor for Credential {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_did(&self) -> String {
        self.did.to_owned()
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

#[cfg(test)]
mod tests {
    use super::*;

    use rst_common::standard::chrono::Utc;
    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::standard::serde_json;
    use rst_common::with_tokio::tokio;

    use prople_crypto::eddsa::keypair::KeyPair;
    use prople_crypto::keysecure::types::ToKeySecure;

    use prople_did_core::did::DID;
    use prople_did_core::doc::types::ToDoc;
    use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;
    use prople_did_core::verifiable::objects::ProofValue;

    use crate::identity::account::Account as AccountIdentity;

    #[derive(Deserialize, Serialize)]
    #[serde(crate = "self::serde")]
    struct FakeCredential {
        pub msg: String,
    }

    fn generate_did() -> DID {
        DID::new()
    }

    fn generate_account(did_vc: DID) -> AccountIdentity {
        let mut did_vc_identity = did_vc.identity().unwrap();
        let did_vc_value_cloned = did_vc_identity.value();

        let did_vc_doc = did_vc_identity
            .build_assertion_method()
            .build_auth_method()
            .to_doc();

        let did_vc_doc_private_keys = did_vc_identity
            .build_private_keys("password".to_string())
            .unwrap();

        let did_vc_keysecure = did_vc
            .account()
            .privkey()
            .to_keysecure("password".to_string())
            .unwrap();

        AccountIdentity {
            id: Uuid::new_v4().to_string(),
            did: did_vc_value_cloned.clone(),
            keysecure: did_vc_keysecure,
            doc: did_vc_doc,
            doc_private_keys: did_vc_doc_private_keys,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_generate_credential_without_params() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();

        let claims = serde_json::to_value(FakeCredential {
            msg: "hello world".to_string(),
        })
        .unwrap();

        let account = generate_account(did_vc);
        let credential_builder = Credential::generate(
            account,
            "password".to_string(),
            did_issuer_value,
            claims,
            None,
        )
        .await;
        assert!(!credential_builder.is_err());

        let credential = credential_builder.unwrap();
        assert!(credential.vc.proof.is_none())
    }

    #[tokio::test]
    async fn test_generate_credential_with_params() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();

        let claims = serde_json::to_value(FakeCredential {
            msg: "hello world".to_string(),
        })
        .unwrap();

        let proof_params = ProofParams {
            id: "uid".to_string(),
            typ: "type".to_string(),
            method: "method".to_string(),
            purpose: "purpose".to_string(),
            cryptosuite: None,
            expires: None,
            nonce: None,
        };

        let account = generate_account(did_vc);
        let credential_builder = Credential::generate(
            account,
            "password".to_string(),
            did_issuer_value,
            claims,
            Some(proof_params),
        )
        .await;
        assert!(!credential_builder.is_err());

        let credential = credential_builder.unwrap();
        assert!(credential.vc.proof.is_some());

        let vc = credential.vc;
        let doc_private_keys = credential.did_vc_doc_private_keys;

        let account_doc_verification_pem_bytes = doc_private_keys
            .clone()
            .authentication
            .map(|val| {
                val.decrypt_verification("password".to_string())
                    .map_err(|err| CredentialError::GenerateError(err.to_string()))
            })
            .ok_or(CredentialError::GenerateError(
                "PrivateKeyPairs is missing".to_string(),
            ));
        assert!(!account_doc_verification_pem_bytes.is_err());

        let account_doc_verification_pem_bytes_unwrap =
            account_doc_verification_pem_bytes.unwrap().unwrap();
        let account_doc_verification_pem =
            String::from_utf8(account_doc_verification_pem_bytes_unwrap)
                .map_err(|err| CredentialError::GenerateError(err.to_string()));
        assert!(!account_doc_verification_pem.is_err());

        let account_doc_keypair = KeyPair::from_pem(account_doc_verification_pem.unwrap())
            .map_err(|err| CredentialError::GenerateError(err.to_string()));
        assert!(!account_doc_keypair.is_err());

        let (vc_original, proof_original) = vc.split_proof();
        let verified = ProofValue::transform_verifier(
            account_doc_keypair.clone().unwrap(),
            vc_original,
            proof_original.clone().unwrap().proof_value,
        );

        assert!(!verified.is_err());
        assert!(verified.unwrap())
    }
}
