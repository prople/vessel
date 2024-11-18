use rst_common::standard::async_trait::async_trait;
use rstdev_storage::engine::rocksdb::executor::Executor;
use rstdev_storage::engine::rocksdb::types::{
    Instruction as DbInstruction, OutputOpts as DbOutput,
};

use prople_vessel_core::identity::verifiable::presentation::types::{
    PresentationEntityAccessor, PresentationError, RepoBuilder, VerifierEntityAccessor,
};
use prople_vessel_core::identity::verifiable::presentation::{Presentation, Verifier};
use prople_vessel_core::identity::verifiable::types::VerifiableError;

use crate::rpc::shared::db::{Bucket as DbBucket, DbError};

const PRESENTATION_KEY_ID: &str = "presentation_id";
const PRESENTATION_MERGE_KEY_DID: &str = "merge_presentation";
const VERIFIER_KEY_ID: &str = "verifier_id";

#[derive(Clone)]
pub struct Repository {
    db: Executor,
}

impl Repository {
    pub fn new(db: Executor) -> Self {
        Self { db }
    }

    fn build_presentation_id_key(&self, val: String) -> String {
        format!("{}:{}", PRESENTATION_KEY_ID.to_string(), val)
    }

    fn build_verifier_id_key(&self, val: String) -> String {
        format!("{}:{}", VERIFIER_KEY_ID.to_string(), val)
    }

    fn build_verifier_merge_id_key(&self, val: String) -> String {
        format!("{}:{}", PRESENTATION_MERGE_KEY_DID.to_string(), val)
    }

    async fn check_merge_presentation_did_exists(&self, key: String) -> bool {
        let value_cred = self
            .db
            .exec(DbInstruction::GetCf { key })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            });

        if value_cred.is_err() {
            return false;
        }

        let checker = {
            match value_cred.unwrap() {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            let bucket: Result<DbBucket<Presentation>, DbError> =
                                DbBucket::try_from(val)
                                    .map_err(|err| DbError::BucketError(err.to_string()));

                            bucket
                        })
                        .ok_or(PresentationError::PresentationNotFound)
                        .map_err(|err| PresentationError::ListError(err.to_string()));

                    output
                }
                _ => Err(PresentationError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        };

        return !checker.is_err();
    }
}

#[async_trait]
impl RepoBuilder for Repository {
    type PresentationEntityAccessor = Presentation;
    type VerifierEntityAccessor = Verifier;

    async fn save(&self, data: &Self::PresentationEntityAccessor) -> Result<(), PresentationError> {
        let presentation_bytes: Vec<u8> = data.to_owned().try_into().map_err(|_| {
            PresentationError::CommonError(VerifiableError::RepoError(
                "unable to convert presentation to bytes".to_string(),
            ))
        })?;

        let presentation_id_key = self.build_presentation_id_key(data.get_id());

        let _ = self
            .db
            .exec(DbInstruction::SaveCf {
                key: presentation_id_key,
                value: presentation_bytes.clone(),
            })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        Ok(())
    }

    async fn save_presentation_verifier(
        &self,
        data: &Self::VerifierEntityAccessor,
    ) -> Result<(), PresentationError> {
        let verifier_bytes: Vec<u8> = data.to_owned().try_into().map_err(|_| {
            PresentationError::CommonError(VerifiableError::RepoError(
                "unable to convert verifier to bytes".to_string(),
            ))
        })?;

        let verifier_id_key = self.build_verifier_id_key(data.get_id());
        let verifier_merge_id_key = self.build_verifier_merge_id_key(data.get_did_verifier());

        let _ = self
            .db
            .exec(DbInstruction::SaveCf {
                key: verifier_id_key,
                value: verifier_bytes.clone(),
            })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        // before we're able to merge some values, we need to make sure that given bucket already exists or not
        let check_bucket_exists = self
            .check_merge_presentation_did_exists(verifier_merge_id_key.clone())
            .await;

        match check_bucket_exists {
            true => {
                let _ = self
                    .db
                    .exec(DbInstruction::MergeCf {
                        key: verifier_merge_id_key.clone(),
                        value: verifier_bytes.clone(),
                    })
                    .await
                    .map_err(|err| {
                        PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
                    })?;
            }
            false => {
                let mut bucket = DbBucket::<Verifier>::new();
                bucket.add(data.to_owned());

                let bucket_bytes: Vec<u8> = bucket.try_into().map_err(|err: DbError| {
                    PresentationError::GenerateJSONError(err.to_string())
                })?;

                let _ = self
                    .db
                    .exec(DbInstruction::SaveCf {
                        key: verifier_merge_id_key.clone(),
                        value: bucket_bytes,
                    })
                    .await
                    .map_err(|err| {
                        PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
                    })?;
            }
        }

        Ok(())
    }

    async fn set_presentation_verifier_verified(
        &self,
        holder: &Self::VerifierEntityAccessor,
    ) -> Result<(), PresentationError> {
        self.save_presentation_verifier(holder).await
    }

    async fn get_by_id(
        &self,
        id: String,
    ) -> Result<Self::PresentationEntityAccessor, PresentationError> {
        let presentation_key = self.build_presentation_id_key(id);
        let value_presentation = self
            .db
            .exec(DbInstruction::GetCf {
                key: presentation_key,
            })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        let presentation = {
            match value_presentation {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            Presentation::try_from(val)
                                .map_err(|err| PresentationError::UnserializeError(err.to_string()))
                        })
                        .ok_or(PresentationError::PresentationNotFound)??;

                    Ok(output)
                }
                _ => Err(PresentationError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        }?;

        Ok(presentation)
    }

    async fn get_verifier_by_id(
        &self,
        id: String,
    ) -> Result<Self::VerifierEntityAccessor, PresentationError> {
        let verifier_key = self.build_verifier_id_key(id);
        let value_verifier = self
            .db
            .exec(DbInstruction::GetCf { key: verifier_key })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        let verifier = {
            match value_verifier {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            Verifier::try_from(val)
                                .map_err(|err| PresentationError::UnserializeError(err.to_string()))
                        })
                        .ok_or(PresentationError::PresentationNotFound)??;

                    Ok(output)
                }
                _ => Err(PresentationError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        }?;

        Ok(verifier)
    }

    async fn list_vps_by_did_verifier(
        &self,
        did_verifier: String,
    ) -> Result<Vec<Self::VerifierEntityAccessor>, PresentationError> {
        let verifier_merge_key = self.build_verifier_merge_id_key(did_verifier);

        let value_bucket = self
            .db
            .exec(DbInstruction::GetCf {
                key: verifier_merge_key,
            })
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        let bucket_verifier = {
            match value_bucket {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            let bucket: Result<DbBucket<Verifier>, DbError> = val.try_into();
                            bucket
                        })
                        .ok_or(PresentationError::VerifierNotFound)?
                        .map_err(|err| PresentationError::ListError(err.to_string()))?;

                    Ok(output)
                }
                _ => Err(PresentationError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        }?;

        let mut output: Vec<Verifier> = Vec::new();
        for cred in bucket_verifier.iterate() {
            output.push(cred.to_owned())
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use multiaddr::{multiaddr, Multiaddr};

    use crate::rpc::shared::helpers::testdb;

    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::with_tokio::tokio;

    use prople_crypto::keysecure::types::{ToKeySecure, Password};

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::keys::{IdentityPrivateKeyPairs, IdentityPrivateKeyPairsBuilder};
    use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
    use prople_did_core::verifiable::objects::{VC, VP};

    use prople_vessel_core::identity::verifiable::credential::types::CredentialEntityAccessor;
    use prople_vessel_core::identity::verifiable::proof::builder::Builder as ProofBuilder;
    use prople_vessel_core::identity::verifiable::proof::types::Params as ProofParams;
    use prople_vessel_core::identity::verifiable::{Credential, Presentation};

    #[derive(Deserialize, Serialize)]
    #[serde(crate = "self::serde")]
    struct FakeCredential {
        pub msg: String,
    }

    fn generate_did() -> DID {
        DID::new()
    }

    fn generate_credentials() -> Vec<Credential> {
        let mut creds = Vec::<Credential>::new();

        let did1 = generate_did();
        let did1_keysecure = did1
            .account()
            .privkey()
            .to_keysecure(Password::from("password".to_string()))
            .unwrap();

        let did2 = generate_did();
        let did2_keysecure = did2
            .account()
            .privkey()
            .to_keysecure(Password::from("password".to_string()))
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

    fn generate_presentation() -> Presentation {
        let did = generate_did();

        let mut identity = did.identity().unwrap();

        identity.build_assertion_method().build_auth_method();
        let doc_priv_keys = identity.build_private_keys("password".to_string()).unwrap();
        let mut vp = VP::new();
        vp.set_holder(identity.value());

        Presentation::new(vp, doc_priv_keys)
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
            vp.add_credential(credential.get_vc().to_owned());
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
    async fn test_save_get_presentation() {
        let presentation = generate_presentation();

        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);
        let try_save = repo.save(&presentation).await;
        assert!(!try_save.is_err());

        let presentation_from_db = repo.get_by_id(presentation.get_id()).await;
        assert!(!presentation_from_db.is_err());
        assert_eq!(
            presentation.get_id(),
            presentation_from_db.unwrap().get_id()
        )
    }

    #[tokio::test]
    async fn test_save_get_verifier() {
        let credentials = generate_credentials();
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let (verifier, _) = generate_verifier(addr, "password".to_string(), credentials);
        assert!(!verifier.is_verified());

        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);
        let try_save = repo.save_presentation_verifier(&verifier).await;
        assert!(!try_save.is_err());

        let verifier_from_db = repo.get_verifier_by_id(verifier.get_id()).await;
        assert!(!verifier_from_db.is_err());

        let verifier_out = verifier_from_db.unwrap();
        assert_eq!(verifier.get_id(), verifier_out.get_id());
        assert_eq!(verifier.get_did_verifier(), verifier_out.get_did_verifier());
    }

    #[tokio::test]
    async fn test_save_get_verifier_update_verified() {
        let credentials = generate_credentials();
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let (verifier, _) = generate_verifier(addr, "password".to_string(), credentials);
        assert!(!verifier.is_verified());

        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);
        let try_save = repo.save_presentation_verifier(&verifier).await;
        assert!(!try_save.is_err());

        let mut verified_cloned = verifier.clone();
        verified_cloned.set_verified();

        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);

        let try_updated = repo
            .set_presentation_verifier_verified(&verified_cloned)
            .await;
        assert!(!try_updated.is_err());

        let verifier_from_db = repo.get_verifier_by_id(verifier.get_id()).await;
        assert!(!verifier_from_db.is_err());

        let verifier_out = verifier_from_db.unwrap();
        assert_eq!(verifier.get_id(), verifier_out.get_id());
        assert!(verifier_out.is_verified())
    }

    #[tokio::test]
    async fn test_save_merge_list_verifiers() {
        let credentials = generate_credentials();
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let (verifier, _) =
            generate_verifier(addr.clone(), "password".to_string(), credentials.clone());
        assert!(!verifier.is_verified());

        let (mut verifier2, _) =
            generate_verifier(addr.clone(), "password".to_string(), credentials.clone());
        assert!(!verifier2.is_verified());

        verifier2.set_did_verifier(verifier.get_did_verifier());

        let (mut verifier3, _) =
            generate_verifier(addr.clone(), "password".to_string(), credentials.clone());
        assert!(!verifier3.is_verified());

        verifier3.set_did_verifier(verifier.get_did_verifier());

        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);

        let try_save1 = repo.save_presentation_verifier(&verifier).await;
        assert!(!try_save1.is_err());

        let try_save2 = repo.save_presentation_verifier(&verifier2).await;
        assert!(!try_save2.is_err());

        let try_save3 = repo.save_presentation_verifier(&verifier3).await;
        assert!(!try_save3.is_err());

        let verifiers_finder = repo
            .list_vps_by_did_verifier(verifier.get_did_verifier())
            .await;
        assert!(!verifiers_finder.is_err());

        let list_verifiers = verifiers_finder.unwrap();
        assert_eq!(list_verifiers.len(), 3)
    }
}
