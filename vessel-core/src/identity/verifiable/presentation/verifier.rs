use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_did_core::doc::types::PublicKeyDecoded;
use prople_did_core::types::VERIFICATION_TYPE_ED25519;
use prople_did_core::verifiable::objects::ProofValue;
use prople_did_core::verifiable::objects::VP;

use crate::identity::account::types::AccountAPI;
use crate::identity::account::URI;

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
        let vp = {
            let internal = self.get_vp();
            match internal.proof {
                Some(_) => Ok(internal),
                None => Err(PresentationError::VerifyError(
                    "proof was missing".to_string(),
                )),
            }
        }?;

        let vp_did_uri = {
            let did_uri = vp
                .clone()
                .holder
                .map(|uri| {
                    let check_did_uri_params = URI::has_params(uri.clone())
                        .map(move |has_params| {
                            if !has_params {
                                return Err(PresentationError::VerifyError(
                                    "current did uri doesn't have any params".to_string(),
                                ));
                            }

                            Ok(uri)
                        })
                        .map_err(|err| PresentationError::VerifyError(err.to_string()))?;

                    check_did_uri_params
                })
                .ok_or(PresentationError::VerifyError("missing vp uri".to_string()))?;

            did_uri
        }?;

        let vp_doc = account
            .resolve_did_doc(vp_did_uri)
            .await
            .map_err(|err| PresentationError::VerifyError(err.to_string()))?;

        let vp_doc_primary_key = {
            let primary =
                vp_doc
                    .authentication
                    .map(|doc| doc)
                    .ok_or(PresentationError::VerifyError(
                        "missing primary keys".to_string(),
                    ))?;

            let key = primary
                .iter()
                .find(|key| {
                    let key = key.to_owned();
                    *key.verification_type.to_string() == VERIFICATION_TYPE_ED25519.to_string()
                })
                .map(|key| key.to_owned());

            key
        }
        .ok_or(PresentationError::VerifyError(
            "doc public keys not found".to_string(),
        ))?;

        let vc_doc_pubkey = {
            let pubkey_decoded = vp_doc_primary_key
                .decode_pub_key()
                .map_err(|err| PresentationError::VerifyError(err.to_string()))?;

            match pubkey_decoded {
                PublicKeyDecoded::EdDSA(pubkey) => Ok(pubkey),
                _ => Err(PresentationError::VerifyError(
                    "the public key should be in EdDSA format, others detected".to_string(),
                )),
            }
        }?;

        let (vp_orig, proof_orig) = vp.clone().split_proof();

        let proof_signature =
            proof_orig
                .map(|proof| proof)
                .ok_or(PresentationError::VerifyError(
                    "proof was missing".to_string(),
                ))?;

        let _ = ProofValue::verify_proof(vc_doc_pubkey, vp_orig, proof_signature.proof_value)
            .map(|verified| {
                if !verified {
                    return Err(PresentationError::VerifyError(
                        "proof signature is invalid".to_string(),
                    ));
                }

                Ok(())
            })
            .map_err(|err| PresentationError::VerifyError(err.to_string()))??;

        let mut verifier_verified = self.clone();
        verifier_verified.is_verified = true;

        Ok(verifier_verified)
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

    use multiaddr::{multiaddr, Multiaddr};

    use rst_common::standard::async_trait::async_trait;
    use rst_common::with_tokio::tokio;

    use prople_crypto::keysecure::types::ToKeySecure;

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::keys::{IdentityPrivateKeyPairs, IdentityPrivateKeyPairsBuilder};
    use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
    use prople_did_core::verifiable::objects::{VC, VP};

    use crate::identity::account::types::{AccountAPI, AccountError};
    use crate::identity::account::Account as AccountIdentity;
    use crate::identity::verifiable::proof::builder::Builder as ProofBuilder;
    use crate::identity::verifiable::proof::types::Params as ProofParams;
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

    fn generate_did() -> DID {
        DID::new()
    }

    fn generate_doc(did: DID) -> Doc {
        let mut did_identity = did.identity().unwrap();
        did_identity.build_assertion_method().build_auth_method();

        did_identity.to_doc()
    }

    fn generate_credentials() -> Vec<Credential> {
        let mut creds = Vec::<Credential>::new();

        let did1 = generate_did();
        let did1_keysecure = did1
            .account()
            .privkey()
            .to_keysecure("password".to_string())
            .unwrap();

        let did2 = generate_did();
        let did2_keysecure = did2
            .account()
            .privkey()
            .to_keysecure("password".to_string())
            .unwrap();

        let vc1 = VC::new("id1".to_string(), did1.identity().unwrap().value());
        let vc2 = VC::new("id2".to_string(), did2.identity().unwrap().value());

        let cred1 = Credential::new(
            "did1".to_string(),
            "did_vc1".to_string(),
            IdentityPrivateKeyPairs::new("id1".to_string()),
            vc1,
            did1_keysecure,
        );

        let cred2 = Credential::new(
            "did2".to_string(),
            "did_vc2".to_string(),
            IdentityPrivateKeyPairs::new("id2".to_string()),
            vc2,
            did2_keysecure,
        );

        creds.push(cred1);
        creds.push(cred2);
        creds
    }

    fn generate_verifier(
        addr: Multiaddr,
        password: String,
        vcs: Vec<Credential>,
    ) -> (Verifier, Doc) {
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

        let mut vp = VP::new();
        vp.add_context(CONTEXT_VC.to_string())
            .add_context(CONTEXT_VC_V2.to_string())
            .add_type("VerifiableCredential".to_string())
            .set_holder(did_uri.clone());

        for credential in vcs.iter() {
            vp.add_credential(credential.vc.to_owned());
        }

        let proof_builder = ProofBuilder::build_proof(
            vp.clone(),
            password,
            did_privkeys.clone(),
            Some(proof_params),
        )
        .unwrap()
        .unwrap();

        vp.add_proof(proof_builder);
        let verifier = Verifier::new(did_value, vp);

        (verifier, did_doc)
    }

    #[tokio::test]
    async fn test_verify_vp_success() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let credentials = generate_credentials();
        let (verifier, doc) =
            generate_verifier(addr, String::from("password".to_string()), credentials);

        let mut mock_account = MockFakeAccountUsecase::new();
        mock_account
            .expect_resolve_did_doc()
            .returning(move |_| Ok(doc.clone()));

        let verified = verifier.verify_vp(mock_account).await;
        assert!(!verified.is_err())
    }

    #[tokio::test]
    async fn test_verify_vp_invalid_doc() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let credentials = generate_credentials();
        let (verifier, _) =
            generate_verifier(addr, String::from("password".to_string()), credentials);

        let fake_doc = generate_doc(generate_did());

        let mut mock_account = MockFakeAccountUsecase::new();
        mock_account
            .expect_resolve_did_doc()
            .returning(move |_| Ok(fake_doc.clone()));

        let verified = verifier.verify_vp(mock_account).await;
        assert!(verified.is_err());

        let verified_err = verified.unwrap_err();
        assert!(matches!(verified_err, PresentationError::VerifyError(_)));

        if let PresentationError::VerifyError(msg) = verified_err {
            assert!(msg.contains("signature invalid"))
        }
    }
}
