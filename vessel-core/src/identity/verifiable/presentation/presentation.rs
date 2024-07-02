use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::uuid::Uuid;

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::types::CONTEXT_VC_V2;
use prople_did_core::verifiable::objects::VP;

use crate::identity::account::types::AccountEntityAccessor;
use crate::identity::verifiable::credential::types::CredentialEntityAccessor;
use crate::identity::verifiable::proof::builder::Builder as ProofBuilder;
use crate::identity::verifiable::proof::types::Params as ProofParams;
use crate::identity::verifiable::types::VerifiableError;

use super::types::{PresentationEntityAccessor, PresentationError, VP_TYPE};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Presentation {
    pub(crate) id: String,
    pub(crate) vp: VP,
    pub(crate) private_keys: IdentityPrivateKeyPairs,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
}

impl ToJSON for Presentation {
    fn to_json(&self) -> Result<String, BaseError> {
        let json_str =
            serde_json::to_string(&self).map_err(|err| BaseError::ToJSONError(err.to_string()))?;

        Ok(json_str)
    }
}

impl TryInto<Vec<u8>> for Presentation {
    type Error = PresentationError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let json = serde_json::to_vec(&self)
            .map_err(|err| PresentationError::GenerateJSONError(err.to_string()))?;
        Ok(json)
    }
}

impl TryFrom<Vec<u8>> for Presentation {
    type Error = PresentationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let presentation: Presentation = serde_json::from_slice(&value)
            .map_err(|err| PresentationError::UnserializeError(err.to_string()))?;
        Ok(presentation)
    }
}

impl PresentationEntityAccessor for Presentation {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_vp(&self) -> VP {
        self.vp.to_owned()
    }

    fn get_private_keys(&self) -> IdentityPrivateKeyPairs {
        self.private_keys.to_owned()
    }

    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at.to_owned()
    }

    fn get_updated_at(&self) -> DateTime<Utc> {
        self.updated_at.to_owned()
    }
}

impl Presentation {
    pub fn new(vp: VP, private_keys: IdentityPrivateKeyPairs) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            vp,
            private_keys,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn generate(
        password: String,
        did_issuer_uri: String,
        account: impl AccountEntityAccessor,
        credentials: Vec<impl CredentialEntityAccessor>,
        proof_params: Option<ProofParams>,
    ) -> Result<Presentation, PresentationError> {
        if password.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("password was missing".to_string()),
            ));
        }

        if did_issuer_uri.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("did_issuer was missing".to_string()),
            ));
        }

        let mut vp = VP::new();
        vp.add_context(CONTEXT_VC_V2.to_string())
            .add_type(String::from(VP_TYPE.to_string()))
            .set_holder(did_issuer_uri.clone());

        for credential in credentials.iter() {
            vp.add_credential(credential.get_vc());
        }

        let account_doc_private_key_pairs = account.get_doc_private_keys();
        let proof_builder = ProofBuilder::build_proof(
            vp.clone(),
            password,
            account_doc_private_key_pairs.clone(),
            proof_params,
        )
        .map_err(|err| PresentationError::GenerateError(err.to_string()))?;

        if let Some(proof) = proof_builder {
            vp.add_proof(proof);
        }

        let presentation = Presentation::new(vp, account_doc_private_key_pairs);
        Ok(presentation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use mockall::predicate::eq;

    use multiaddr::Multiaddr;
    use rst_common::standard::async_trait::async_trait;
    use rst_common::standard::serde_json;
    use rst_common::with_tokio::tokio;

    use prople_crypto::keysecure::types::ToKeySecure;

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;

    use crate::identity::account::types::{AccountAPI, AccountError};
    use crate::identity::account::Account as AccountIdentity;
    use crate::identity::verifiable::Credential;

    mock!(
        FakeAccountUsecase{}

        impl Clone for FakeAccountUsecase {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl AccountAPI for FakeAccountUsecase {
            type EntityAccessor = AccountIdentity;

            async fn generate_did(&self, password: String, current_addr: Option<Multiaddr>) -> Result<AccountIdentity, AccountError>;
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
            did_uri: "did-uri".to_string(),
            keysecure: did_vc_keysecure,
            doc: did_vc_doc,
            doc_private_keys: did_vc_doc_private_keys,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_generate_without_params() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let mut expected = MockFakeAccountUsecase::new();
        expected
            .expect_generate_did()
            .with(eq("password".to_string()), eq(None))
            .return_once(move |_, _| {
                let mut did_vc_identity = did_vc_cloned.identity().unwrap();
                let did_vc_value_cloned = did_vc_identity.value();

                let did_vc_doc = did_vc_identity
                    .build_assertion_method()
                    .build_auth_method()
                    .to_doc();

                let did_vc_doc_private_keys = did_vc_identity
                    .build_private_keys("password".to_string())
                    .unwrap();

                let did_vc_keysecure = did_vc_cloned
                    .account()
                    .privkey()
                    .to_keysecure("password".to_string())
                    .unwrap();

                Ok(AccountIdentity {
                    id: Uuid::new_v4().to_string(),
                    did: did_vc_value_cloned.clone(),
                    did_uri: "did-uri".to_string(),
                    keysecure: did_vc_keysecure,
                    doc: did_vc_doc,
                    doc_private_keys: did_vc_doc_private_keys,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                })
            });

        let claims = serde_json::to_value(FakeCredential {
            msg: "hello world".to_string(),
        })
        .unwrap();

        let account_generated = generate_account(did_vc.clone());
        let credential_builder = Credential::generate(
            account_generated,
            "password".to_string(),
            did_issuer_value.clone(),
            claims,
            None,
        )
        .await;
        assert!(!credential_builder.is_err());

        let account_builder = AccountIdentity::generate("password".to_string(), None);
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();
        let credential = credential_builder.unwrap();
        let presentation_builder = Presentation::generate(
            "password".to_string(),
            did_issuer_value,
            account,
            vec![credential],
            None,
        );
        assert!(!presentation_builder.is_err());
    }
}
