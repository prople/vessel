use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_did_core::doc::types::PublicKeyDecoded;
use prople_did_core::verifiable::objects::VP;

use crate::identity::account::types::AccountAPI;
use crate::identity::verifiable::proof::verifier::Verifier as ProofVerifier;

use super::types::{PresentationError, VerifierEntityAccessor};

/// `CredentialHolder` is an entity used by a `Holder` to save incoming [`VC`] that sent
/// from `Issuer`
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Verifier {
    pub(crate) id: String,
    pub(crate) did_verifier: String,
    pub(crate) vp: VP,
    pub(crate) is_verified: bool,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
}

impl Verifier {
    pub fn new(did_verifier: String, vp: VP) -> Self {
        let uid = Uuid::new_v4().to_string();
        Self {
            id: uid,
            did_verifier,
            vp,
            is_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn set_verified(&mut self) -> &mut Self {
        self.is_verified = true;
        self
    }

    pub fn set_did_verifier(&mut self, did_verifier: String) -> &mut Self {
        self.did_verifier = did_verifier;
        self
    }

    pub async fn verify_vp(&self, account: impl AccountAPI) -> Result<Self, PresentationError> {
        // get VP from verifier
        let vp = self.vp.clone();

        // get the holder from VP
        let holder = vp.clone().holder.ok_or(PresentationError::HolderNotFound)?;

        // resolve the holder DID doc
        let did_doc = account
            .resolve_did_uri(holder)
            .await
            .map_err(|err| PresentationError::VerifyError(err.to_string()))?;

        // start iterate over doc assertions
        // for each iteration, it will contain a `Primary` object
        // and we will check if the `Primary` object is a `PublicKeyDecoded`
        // if it is, we will check if the `PublicKeyDecoded` is a `EdDSA` key
        // if it is, we will verify the proof using the `ProofVerifier`
        let assertions: Vec<_> = did_doc
            .assertion
            .ok_or(PresentationError::VerifyError(
                "assertion key not found".to_string(),
            ))?
            .iter()
            .map(|val| val.decode_pub_key().ok())
            .filter(|val| match val {
                Some(PublicKeyDecoded::EdDSA(pubkey)) => {
                    let verified = ProofVerifier::verify_proof(vp.clone(), pubkey.clone());

                    match verified {
                        Ok(_) => true,
                        Err(_) => false,
                    }
                }
                _ => false,
            })
            .collect();

        match assertions.len() {
            0 => Err(PresentationError::VerifyError(
                "signature invalid".to_string(),
            )),
            _ => {
                // if all assertions are valid, set the verifier to verified
                let mut verifier = self.clone();
                verifier.set_verified();
                Ok(verifier)
            }
        }
    }
}

impl ToJSON for Verifier {
    fn to_json(&self) -> Result<String, BaseError> {
        let json_str =
            serde_json::to_string(&self).map_err(|err| BaseError::ToJSONError(err.to_string()))?;

        Ok(json_str)
    }
}

impl TryInto<Vec<u8>> for Verifier {
    type Error = PresentationError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let json = serde_json::to_vec(&self)
            .map_err(|err| PresentationError::GenerateJSONError(err.to_string()))?;
        Ok(json)
    }
}

impl TryFrom<Vec<u8>> for Verifier {
    type Error = PresentationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let verifier: Verifier = serde_json::from_slice(&value)
            .map_err(|err| PresentationError::UnserializeError(err.to_string()))?;
        Ok(verifier)
    }
}

impl VerifierEntityAccessor for Verifier {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_vp(&self) -> VP {
        self.vp.to_owned()
    }

    fn is_verified(&self) -> bool {
        self.is_verified.to_owned()
    }

    fn get_did_verifier(&self) -> String {
        self.did_verifier.to_owned()
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

    use mockall::mock;
    use mockall::predicate::*;

    use rst_common::standard::async_trait::async_trait;
    use rst_common::standard::serde_json::Value;
    use rst_common::with_tokio::tokio;

    use prople_crypto::eddsa::keypair::KeyPair;

    use prople_did_core::did::query::Params;
    use prople_did_core::did::DID;
    use prople_did_core::doc::types::Doc;
    use prople_did_core::keys::IdentityPrivateKeyPairs;

    use crate::identity::account::types::AccountEntityAccessor;
    use crate::identity::account::types::{AccountAPI, AccountError};
    use crate::identity::account::Account as AccountIdentity;
    use crate::identity::verifiable::credential::types::CredentialEntityAccessor;
    use crate::identity::verifiable::proof::types::ProofError;
    use crate::identity::verifiable::proof::verifier::Verifier as ProofVerifier;
    use crate::identity::verifiable::{Credential, Presentation};

    #[derive(Deserialize, Serialize)]
    #[serde(crate = "self::serde")]
    struct FakeCredential {
        pub msg: String,
    }

    async fn generate_creds(
        did_issuer: DID,
        claims: Value,
        account: AccountIdentity,
    ) -> Vec<impl CredentialEntityAccessor> {
        let did_issuer_identity = did_issuer.clone().identity().unwrap();
        let cred = Credential::generate(
            account,
            "password".to_string(),
            did_issuer_identity.value(),
            claims,
        )
        .await
        .unwrap();

        vec![cred]
    }

    fn generate_presentation(
        did_issuer: DID,
        account: impl AccountEntityAccessor,
        creds: Vec<impl CredentialEntityAccessor>,
    ) -> Presentation {
        let presentation = Presentation::generate(
            "password".to_string(),
            did_issuer.identity().unwrap().value(),
            account,
            creds,
        );

        presentation.unwrap()
    }

    fn generate_keypair(keypairs: IdentityPrivateKeyPairs) -> Result<KeyPair, ProofError> {
        let account_doc_verification_pem_bytes = keypairs
            .clone()
            .assertion
            .map(|val| {
                val.decrypt_verification("password".to_string())
                    .map_err(|err| ProofError::BuildError(err.to_string()))
            })
            .ok_or(ProofError::BuildError(
                "PrivateKeyPairs is missing".to_string(),
            ))??;

        let account_doc_verification_pem = String::from_utf8(account_doc_verification_pem_bytes)
            .map_err(|err| ProofError::BuildError(err.to_string()))?;

        KeyPair::from_pem(account_doc_verification_pem)
            .map_err(|err| ProofError::BuildError(err.to_string()))
    }

    mock!(
        FakeAccountUsecase{}

        impl Clone for FakeAccountUsecase {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl AccountAPI for FakeAccountUsecase {
            type EntityAccessor = AccountIdentity;

            async fn generate_did(&self, password: String) -> Result<AccountIdentity, AccountError>;
            async fn build_did_uri(
                &self,
                did: String,
                password: String,
                params: Option<Params>,
            ) -> Result<String, AccountError>;
            async fn resolve_did_uri(&self, uri: String) -> Result<Doc, AccountError>;
            async fn resolve_did_doc(&self, did: String) -> Result<Doc, AccountError>;
            async fn remove_did(&self, did: String) -> Result<(), AccountError>;
            async fn get_account_did(&self, did: String) -> Result<AccountIdentity, AccountError>;
        }
    );

    mod expect_success {
        use super::*;

        #[tokio::test]
        async fn test_verify_vp_using_raw_verifier() {
            let issuer_account = AccountIdentity::generate("password".to_string()).unwrap();
            let issuer_doc = issuer_account.get_doc();
            let issuer_did =
                DID::from_keysecure("password".to_string(), issuer_account.get_keysecure())
                    .unwrap();
            let issuer_doc_private_keys = issuer_account.get_doc_private_keys();

            let issuer_doc_cloned = issuer_doc.clone();
            let issuer_did_cloned = issuer_did.clone();

            let mut mocked_account = MockFakeAccountUsecase::new();
            mocked_account
                .expect_resolve_did_uri()
                .with(eq(issuer_did_cloned.identity().unwrap().value()))
                .return_once(|_| Ok(issuer_doc_cloned));

            let claims = FakeCredential {
                msg: "hello world".to_string(),
            };

            let credential = serde_json::to_value(claims).unwrap();
            let vc_account = AccountIdentity::generate("password".to_string()).unwrap();
            let creds = generate_creds(issuer_did.clone(), credential, vc_account.clone()).await;
            let presentation =
                generate_presentation(issuer_did.clone(), issuer_account.clone(), creds.clone());

            let keypair = generate_keypair(issuer_doc_private_keys).unwrap();
            let pubkey = keypair.pub_key();
            let verifier = ProofVerifier::verify_proof(presentation.vp.clone(), pubkey.clone());
            assert!(!verifier.is_err());
        }

        #[tokio::test]
        async fn test_verify_vp() {
            let issuer_account = AccountIdentity::generate("password".to_string()).unwrap();
            let issuer_doc = issuer_account.get_doc();
            let issuer_did =
                DID::from_keysecure("password".to_string(), issuer_account.get_keysecure())
                    .unwrap();

            let issuer_doc_cloned = issuer_doc.clone();
            let issuer_did_cloned = issuer_did.clone();

            let mut mocked_account = MockFakeAccountUsecase::new();
            mocked_account.expect_clone().once().return_once(move || {
                let did_str = issuer_did_cloned.identity().unwrap().value();

                let mut mocked = MockFakeAccountUsecase::new();
                mocked
                    .expect_resolve_did_uri()
                    .with(eq(did_str))
                    .return_once(|_| Ok(issuer_doc_cloned));

                mocked
            });

            let claims = FakeCredential {
                msg: "hello world".to_string(),
            };

            let credential = serde_json::to_value(claims).unwrap();
            let vc_account = AccountIdentity::generate("password".to_string()).unwrap();
            let creds = generate_creds(issuer_did.clone(), credential, vc_account.clone()).await;
            let presentation =
                generate_presentation(issuer_did.clone(), issuer_account.clone(), creds.clone());

            let verifier = Verifier::new(issuer_account.get_did(), presentation.vp);
            let verified = verifier.verify_vp(mocked_account.clone()).await;
            assert!(!verified.is_err());
            assert!(verified.clone().unwrap().is_verified());
        }
    }

    mod expect_error {
        use super::*;

        #[tokio::test]
        async fn test_verify_vp_error_resolve() {
            let issuer_account = AccountIdentity::generate("password".to_string()).unwrap();
            let issuer_did =
                DID::from_keysecure("password".to_string(), issuer_account.get_keysecure())
                    .unwrap();

            let issuer_did_cloned = issuer_did.clone();

            let mut mock_account = MockFakeAccountUsecase::new();
            mock_account.expect_clone().once().return_once(move || {
                let did_str = issuer_did_cloned.identity().unwrap().value();

                let mut mocked = MockFakeAccountUsecase::new();
                mocked
                    .expect_resolve_did_uri()
                    .with(eq(did_str))
                    .return_once(|_| {
                        Err(AccountError::ResolveDIDError("error resolve".to_string()))
                    });

                mocked
            });

            let claims = FakeCredential {
                msg: "hello world".to_string(),
            };

            let credential = serde_json::to_value(claims).unwrap();
            let vc_account = AccountIdentity::generate("password".to_string()).unwrap();
            let creds = generate_creds(issuer_did.clone(), credential, vc_account.clone()).await;
            let presentation =
                generate_presentation(issuer_did.clone(), issuer_account.clone(), creds.clone());

            // create a verifier with the vp
            let verifier = Verifier::new(issuer_account.get_did(), presentation.vp);

            // verify the vp
            let verified = verifier.verify_vp(mock_account.clone()).await;
            assert!(verified.is_err());
            assert!(matches!(verified, Err(PresentationError::VerifyError(_))));
            assert!(verified.unwrap_err().to_string().contains("error resolve"));
        }

        #[tokio::test]
        async fn test_verify_vp_invalid() {
            let issuer_account = AccountIdentity::generate("password".to_string()).unwrap();
            let issuer_did =
                DID::from_keysecure("password".to_string(), issuer_account.get_keysecure())
                    .unwrap();

            let issuer_did_cloned = issuer_did.clone();

            let mut mock_account = MockFakeAccountUsecase::new();
            mock_account.expect_clone().once().return_once(move || {
                let issuer_fake = AccountIdentity::generate("password".to_string()).unwrap();
                let did_str = issuer_did_cloned.identity().unwrap().value();
                assert_ne!(issuer_fake.get_did().to_string(), did_str);

                let mut mocked = MockFakeAccountUsecase::new();
                mocked
                    .expect_resolve_did_uri()
                    .with(eq(did_str))
                    .return_once(move |_| Ok(issuer_fake.get_doc()));

                mocked
            });

            let claims = FakeCredential {
                msg: "hello world".to_string(),
            };

            let credential = serde_json::to_value(claims).unwrap();
            let vc_account = AccountIdentity::generate("password".to_string()).unwrap();
            let creds = generate_creds(issuer_did.clone(), credential, vc_account.clone()).await;
            let presentation =
                generate_presentation(issuer_did.clone(), issuer_account.clone(), creds.clone());

            let verifier = Verifier::new(issuer_account.get_did(), presentation.vp);
            let verified = verifier.verify_vp(mock_account.clone()).await;
            assert!(verified.is_err());
            assert!(matches!(verified, Err(PresentationError::VerifyError(_))));
            assert!(verified
                .unwrap_err()
                .to_string()
                .contains("signature invalid"));
        }
    }
}
