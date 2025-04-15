use prople_crypto::eddsa::pubkey::PubKey;

use prople_did_core::verifiable::proof::types::{ProofPurpose, Proofable};
use prople_did_core::verifiable::proof::DataIntegrityEddsaJcs2022;

use super::types::ProofError;

pub struct Verifier;

impl Verifier {
    pub fn verify_proof<TDoc>(secured: TDoc, pubkey: PubKey) -> Result<(), ProofError>
    where
        TDoc: Proofable,
    {
        let bytes_parsed = secured
            .to_json()
            .map_err(|err| ProofError::VerificationError(err.to_string()))?
            .to_bytes();

        let proof_integrity = DataIntegrityEddsaJcs2022::<TDoc>::new().build();

        proof_integrity
            .verify_proof(pubkey, bytes_parsed, ProofPurpose::AssertionMethod)
            .map_err(|err| ProofError::VerificationError(err.to_string()))
            .and_then(|val| match val.verified {
                true => Ok(()),
                _ => Err(ProofError::VerificationError(
                    "given proof not verified".to_string(),
                )),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::standard::serde_json;

    use prople_crypto::eddsa::keypair::KeyPair;

    use prople_did_core::did::DID;
    use prople_did_core::doc::types::ToDoc;
    use prople_did_core::keys::{IdentityPrivateKeyPairs, IdentityPrivateKeyPairsBuilder};
    use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
    use prople_did_core::verifiable::objects::VC;

    use crate::identity::verifiable::proof::builder::Builder;

    #[derive(Deserialize, Serialize)]
    #[serde(crate = "self::serde")]
    struct FakeCredential {
        pub msg: String,
    }

    fn generate_did() -> DID {
        DID::new()
    }

    fn generate_vc() -> (VC, IdentityPrivateKeyPairs) {
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

        let secured = Builder::build_proof(
            vc.clone(),
            "password".to_string(),
            did_vc_doc_private_keys.clone(),
        );

        vc.setup_proof(secured.unwrap().unwrap());
        (vc, did_vc_doc_private_keys)
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

    mod expect_success {
        use super::*;

        #[test]
        fn test_verify_proof() {
            let (vc, did_vc_doc_private_keys) = generate_vc();

            let account_doc_keypair = generate_keypair(did_vc_doc_private_keys);
            assert!(!account_doc_keypair.is_err());

            let keypair = account_doc_keypair.unwrap();
            let pubkey = keypair.pub_key();

            let verify_proof = Verifier::verify_proof(vc, pubkey);
            assert!(!verify_proof.is_err());
        }

        #[test]
        fn test_verify_failed() {
            let (vc, _) = generate_vc();

            let keypair = KeyPair::generate();
            let pubkey = keypair.pub_key();

            let verify_proof = Verifier::verify_proof(vc, pubkey);
            assert!(verify_proof.is_err());

            let err_msg = verify_proof.unwrap_err();
            assert!(err_msg.to_string().contains("Verification equation"));
        }
    }
}
