use rst_common::standard::chrono::Utc;
use rst_common::standard::uuid::Uuid;

use prople_crypto::eddsa::keypair::KeyPair;

use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::verifiable::proof::types::{ProofPurpose, Proofable};
use prople_did_core::verifiable::proof::{DataIntegrityEddsaJcs2022, Proof};

use super::types::ProofError;

pub struct Builder;

impl Builder {
    pub fn build_proof<TDoc>(
        unsecured: TDoc,
        password: String,
        doc_private_keys: IdentityPrivateKeyPairs,
    ) -> Result<Option<Proof>, ProofError>
    where
        TDoc: Proofable,
    {
        let account_doc_keypair = {
            let account_doc_password = password.clone();
            let account_doc_verification_pem_bytes = doc_private_keys
                .clone()
                .assertion
                .map(|val| {
                    val.decrypt_verification(account_doc_password.clone())
                        .map_err(|err| ProofError::BuildError(err.to_string()))
                })
                .ok_or(ProofError::BuildError(
                    "PrivateKeyPairs is missing".to_string(),
                ))??;

            let account_doc_verification_pem =
                String::from_utf8(account_doc_verification_pem_bytes)
                    .map_err(|err| ProofError::BuildError(err.to_string()))?;

            let keypair = KeyPair::from_pem(account_doc_verification_pem)
                .map_err(|err| ProofError::BuildError(err.to_string()))?;
            keypair
        };

        let proof_integrity = {
            let proof_integrity_proxy = DataIntegrityEddsaJcs2022::<TDoc>::new();
            proof_integrity_proxy.build()
        };

        let uid = Uuid::new_v4().to_string();

        let mut proof = Proof::new(uid);
        proof.purpose(ProofPurpose::AssertionMethod.to_string());
        proof.created(Utc::now().to_string());

        let integrity = proof_integrity
            .add_proof(account_doc_keypair, unsecured, proof)
            .map_err(|err| ProofError::BuildError(err.to_string()))?;

        let proof_rebuild = integrity.get_proof();
        Ok(proof_rebuild)
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

        let proof_builder = Builder::build_proof(
            vc.clone(),
            "password".to_string(),
            did_vc_doc_private_keys.clone(),
        );

        assert!(!proof_builder.is_err());

        let proof = proof_builder.unwrap();
        assert!(proof.is_some());

        let account_doc_verification_pem_bytes = did_vc_doc_private_keys
            .clone()
            .assertion
            .map(|val| {
                val.decrypt_verification("password".to_string())
                    .map_err(|err| ProofError::BuildError(err.to_string()))
            })
            .ok_or(ProofError::BuildError(
                "PrivateKeyPairs is missing".to_string(),
            ));
        assert!(!account_doc_verification_pem_bytes.is_err());

        let account_doc_verification_pem_bytes_unwrap =
            account_doc_verification_pem_bytes.unwrap().unwrap();
        let account_doc_verification_pem =
            String::from_utf8(account_doc_verification_pem_bytes_unwrap)
                .map_err(|err| ProofError::BuildError(err.to_string()));
        assert!(!account_doc_verification_pem.is_err());

        let account_doc_keypair = KeyPair::from_pem(account_doc_verification_pem.unwrap())
            .map_err(|err| ProofError::BuildError(err.to_string()));
        assert!(!account_doc_keypair.is_err());
    }
}
