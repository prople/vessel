use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_did_core::verifiable::objects::VC;

use crate::identity::account::types::AccountAPI;

use super::types::{CredentialError, HolderEntityAccessor};

/// `CredentialHolder` is an entity used by a `Holder` to save incoming [`VC`] that sent
/// from `Issuer`
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Holder {
    pub(crate) id: String,
    pub(crate) did_holder: String,
    pub(crate) vc: VC,

    #[serde(rename = "isVerified")]
    pub(crate) is_verified: bool,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
}

impl Holder {
    pub fn new(did_holder: String, vc: VC) -> Self {
        let uid = Uuid::new_v4().to_string();
        Self {
            id: uid,
            did_holder,
            vc,
            is_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn set_verified(&mut self) -> &mut Self {
        self.is_verified = true;
        self
    }

    pub async fn verify_vc(&self, _: impl AccountAPI) -> Result<Self, CredentialError> {
        let mut verified_holder = self.clone();
        verified_holder.is_verified = true;

        Ok(verified_holder)
    }
}

impl ToJSON for Holder {
    fn to_json(&self) -> Result<String, BaseError> {
        let json_str =
            serde_json::to_string(&self).map_err(|err| BaseError::ToJSONError(err.to_string()))?;

        Ok(json_str)
    }
}

impl TryInto<Vec<u8>> for Holder {
    type Error = CredentialError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let json = serde_json::to_vec(&self)
            .map_err(|err| CredentialError::GenerateJSONError(err.to_string()))?;
        Ok(json)
    }
}

impl TryFrom<Vec<u8>> for Holder {
    type Error = CredentialError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let holder: Holder = serde_json::from_slice(&value)
            .map_err(|err| CredentialError::UnserializeError(err.to_string()))?;
        Ok(holder)
    }
}

impl HolderEntityAccessor for Holder {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_vc(&self) -> VC {
        self.vc.to_owned()
    }

    fn get_is_verified(&self) -> bool {
        self.is_verified.to_owned()
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

    use multiaddr::{multiaddr, Multiaddr};

    use rst_common::standard::async_trait::async_trait;
    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::standard::serde_json;
    use rst_common::with_tokio::tokio;

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;
    use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};

    use crate::identity::account::types::{AccountAPI, AccountError};
    use crate::identity::account::Account as AccountIdentity;
    use crate::identity::verifiable::proof::builder::Builder as ProofBuilder;
    use crate::identity::verifiable::proof::types::Params as ProofParams;

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

    #[derive(Deserialize, Serialize)]
    #[serde(crate = "self::serde")]
    struct FakeCredential {
        pub msg: String,
    }

    fn generate_did() -> DID {
        DID::new()
    }

    fn generate_doc(did: DID) -> Doc {
        let mut did_identity = did.identity().unwrap();
        did_identity.build_assertion_method().build_auth_method();

        did_identity.to_doc()
    }

    fn generate_holder(addr: Multiaddr, password: String) -> (Holder, Doc) {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did = generate_did();
        let did_value = did.identity().unwrap().value();

        let mut did_identity = did.identity().unwrap();
        did_identity.build_assertion_method().build_auth_method();

        let did_doc = did_identity.to_doc();
        let did_privkeys = did_identity.build_private_keys(password.clone()).unwrap();

        let mut query_params = Params::default();
        query_params.address = Some(addr.to_string());

        let did_uri = did.build_uri(Some(query_params)).unwrap();

        let proof_params = ProofParams {
            id: "uid".to_string(),
            typ: "type".to_string(),
            method: "method".to_string(),
            purpose: "purpose".to_string(),
            cryptosuite: None,
            expires: None,
            nonce: None,
        };

        let cred_value = serde_json::to_value(FakeCredential {
            msg: "hello world".to_string(),
        })
        .unwrap();

        let mut vc = VC::new(did_uri, did_issuer_value);
        vc.add_context(CONTEXT_VC.to_string())
            .add_context(CONTEXT_VC_V2.to_string())
            .add_type("VerifiableCredential".to_string())
            .set_credential(cred_value);

        let proof_builder = ProofBuilder::build_proof(
            vc.clone(),
            password,
            did_privkeys.clone(),
            Some(proof_params),
        )
        .unwrap()
        .unwrap();

        vc.proof(proof_builder);
        let holder = Holder::new(did_value, vc);

        (holder, did_doc)
    }

    #[tokio::test]
    async fn test_holder_verify_success() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let (holder, doc) = generate_holder(addr, String::from("password".to_string()));

        let mut mock_account = MockFakeAccountUsecase::new();
        mock_account
            .expect_resolve_did_doc()
            .returning(move |_| Ok(doc.clone()));

        let verified = holder.verify_vc(mock_account).await;
        assert!(!verified.is_err())
    }

    #[tokio::test]
    async fn test_holder_verify_with_invalid_doc() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let (holder, _) = generate_holder(addr, String::from("password".to_string()));

        let fake_doc = generate_doc(generate_did());

        let mut mock_account = MockFakeAccountUsecase::new();
        mock_account
            .expect_resolve_did_doc()
            .returning(move |_| Ok(fake_doc.clone()));

        let verified = holder.verify_vc(mock_account).await;
        assert!(verified.is_err());

        let verified_err = verified.unwrap_err();
        assert!(matches!(verified_err, CredentialError::VerifyError(_)));

        if let CredentialError::VerifyError(msg) = verified_err {
            assert!(msg.contains("signature invalid"))
        }
    }
}
