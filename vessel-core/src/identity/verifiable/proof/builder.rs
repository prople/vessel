use rst_common::standard::uuid::Uuid;

use prople_crypto::eddsa::keypair::KeyPair;

use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::types::ToJCS;
use prople_did_core::verifiable::objects::{Proof, ProofValue};

use crate::identity::verifiable::types::VerifiableError;

use super::types::Params;

pub struct Builder;

impl Builder {
    pub fn build_proof(
        unsecured: impl ToJCS,
        password: String,
        doc_private_keys: IdentityPrivateKeyPairs,
        params: Option<Params>,
    ) -> Result<Option<Proof>, VerifiableError> {
        if params.is_none() {
            return Ok(None);
        }

        let proof_params = params.unwrap();
        let account_doc_password = password.clone();
        let account_doc_verification_pem_bytes = doc_private_keys
            .clone()
            .authentication
            .map(|val| {
                val.decrypt_verification(account_doc_password.clone())
                    .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))
            })
            .ok_or(VerifiableError::VCGenerateError(
                "PrivateKeyPairs is missing".to_string(),
            ))??;

        let account_doc_verification_pem = String::from_utf8(account_doc_verification_pem_bytes)
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let account_doc_keypair = KeyPair::from_pem(account_doc_verification_pem)
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let (_, sig) = ProofValue::transform(account_doc_keypair, unsecured)
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let uid = Uuid::new_v4().to_string();

        let mut proof = Proof::new(uid);
        proof.typ(proof_params.typ);
        proof.purpose(proof_params.purpose);
        proof.method(proof_params.method);
        proof.set_signature_as_string(sig);

        if let Some(cryptosuite) = proof_params.cryptosuite {
            proof.cryptosuite(cryptosuite);
        }

        if let Some(nonce) = proof_params.nonce {
            proof.nonce(nonce);
        }

        if let Some(expiry) = proof_params.expires {
            proof.expires(expiry);
        }

        Ok(Some(proof))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use prople_did_core::did::DID;
    use prople_did_core::doc::types::ToDoc;
    use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;
    use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
    use prople_did_core::verifiable::objects::VC;

    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::standard::serde_json;

    #[derive(Deserialize, Serialize)]
    #[serde(crate = "self::serde")]
    struct FakeCredential {
        pub msg: String,
    }

    fn generate_did() -> DID {
        DID::new()
    }

    #[test]
    fn test_build_proof() {
        let did_issuer = generate_did();
        let did_issue_identity = did_issuer.identity().unwrap();

        let did_vc = generate_did();
        let mut did_vc_identity = did_vc.identity().unwrap();

        let _ = did_vc_identity
            .build_assertion_method()
            .build_auth_method()
            .to_doc();

        let did_vc_doc_private_keys = did_vc_identity
            .build_private_keys("password".to_string())
            .unwrap();

        let claims = FakeCredential {
            msg: "hello world".to_string(),
        };

        let credential = serde_json::to_value(claims).unwrap();

        let mut vc = VC::new(did_vc_identity.value(), did_issue_identity.value());
        vc.add_context(CONTEXT_VC.to_string())
            .add_context(CONTEXT_VC_V2.to_string())
            .add_type("VerifiableCredential".to_string())
            .set_credential(credential);

        let proof_params = Params {
            id: "uid".to_string(),
            typ: "type".to_string(),
            method: "method".to_string(),
            purpose: "purpose".to_string(),
            cryptosuite: None,
            expires: None,
            nonce: None,
        };

        let proof_builder = Builder::build_proof(
            vc.clone(),
            "password".to_string(),
            did_vc_doc_private_keys.clone(),
            Some(proof_params),
        );

        assert!(!proof_builder.is_err());

        let proof = proof_builder.unwrap();
        assert!(proof.is_some());

        let account_doc_verification_pem_bytes = did_vc_doc_private_keys
            .clone()
            .authentication
            .map(|val| {
                val.decrypt_verification("password".to_string())
                    .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))
            })
            .ok_or(VerifiableError::VCGenerateError(
                "PrivateKeyPairs is missing".to_string(),
            ));
        assert!(!account_doc_verification_pem_bytes.is_err());

        let account_doc_verification_pem_bytes_unwrap =
            account_doc_verification_pem_bytes.unwrap().unwrap();
        let account_doc_verification_pem =
            String::from_utf8(account_doc_verification_pem_bytes_unwrap)
                .map_err(|err| VerifiableError::VCGenerateError(err.to_string()));
        assert!(!account_doc_verification_pem.is_err());

        let account_doc_keypair = KeyPair::from_pem(account_doc_verification_pem.unwrap())
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()));
        assert!(!account_doc_keypair.is_err());

        let verified = ProofValue::transform_verifier(
            account_doc_keypair.clone().unwrap(),
            vc,
            proof.clone().unwrap().proof_value,
        );
        assert!(!verified.is_err());
        assert!(verified.unwrap())
    }

    #[test]
    fn test_build_proof_no_params() {
        let did_issuer = generate_did();
        let did_issue_identity = did_issuer.identity().unwrap();

        let did_vc = generate_did();
        let mut did_vc_identity = did_vc.identity().unwrap();

        let _ = did_vc_identity
            .build_assertion_method()
            .build_auth_method()
            .to_doc();

        let did_vc_doc_private_keys = did_vc_identity
            .build_private_keys("password".to_string())
            .unwrap();

        let claims = FakeCredential {
            msg: "hello world".to_string(),
        };

        let credential = serde_json::to_value(claims).unwrap();

        let mut vc = VC::new(did_vc_identity.value(), did_issue_identity.value());
        vc.add_context(CONTEXT_VC.to_string())
            .add_context(CONTEXT_VC_V2.to_string())
            .add_type("VerifiableCredential".to_string())
            .set_credential(credential);

        let proof_builder = Builder::build_proof(
            vc.clone(),
            "password".to_string(),
            did_vc_doc_private_keys.clone(),
            None,
        );

        assert!(!proof_builder.is_err());
        assert!(proof_builder.unwrap().is_none())
    }
}
