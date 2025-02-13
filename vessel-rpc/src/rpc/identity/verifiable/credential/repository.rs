use rst_common::standard::async_trait::async_trait;
use rstdev_storage::engine::rocksdb::executor::Executor;
use rstdev_storage::engine::rocksdb::types::{
    Instruction as DbInstruction, OutputOpts as DbOutput,
};

use prople_vessel_core::identity::verifiable::credential::types::{
    CredentialEntityAccessor, CredentialError, HolderEntityAccessor, RepoBuilder,
};

use prople_vessel_core::identity::verifiable::types::{PaginationParams, VerifiableError};
use prople_vessel_core::identity::verifiable::{Credential, Holder};

use crate::rpc::shared::db::{Bucket as DbBucket, DbError};

const CREDENTIAL_KEY_ID: &str = "credential_id";
const CREDENTIAL_MERGE_KEY_DID: &str = "merge_credential";
const HOLDER_KEY_ID: &str = "holder_id";

#[derive(Clone)]
pub struct Repository {
    db: Executor,
}

impl Repository {
    pub fn new(db: Executor) -> Self {
        Self { db }
    }

    fn build_credential_id_key(&self, val: String) -> String {
        format!("{}:{}", CREDENTIAL_KEY_ID.to_string(), val)
    }

    fn build_holder_key(&self, val: String) -> String {
        format!("{}:{}", HOLDER_KEY_ID.to_string(), val)
    }

    fn build_credential_merge_did_key(&self, val: String) -> String {
        format!("{}:{}", CREDENTIAL_MERGE_KEY_DID.to_string(), val)
    }

    async fn check_merge_credential_did_exists(&self, key: String) -> bool {
        let value_cred = self
            .db
            .exec(DbInstruction::GetCf { key })
            .await
            .map_err(|err| {
                CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
            });

        if value_cred.is_err() {
            return false;
        }

        let checker = {
            match value_cred.unwrap() {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            let bucket: Result<DbBucket<Credential>, DbError> =
                                DbBucket::try_from(val)
                                    .map_err(|err| DbError::BucketError(err.to_string()));

                            bucket
                        })
                        .ok_or(CredentialError::CredentialNotFound)
                        .map_err(|err| CredentialError::ListError(err.to_string()));

                    output
                }
                _ => Err(CredentialError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        };

        return !checker.is_err();
    }
}

#[async_trait]
impl RepoBuilder for Repository {
    type CredentialEntityAccessor = Credential;
    type HolderEntityAccessor = Holder;

    async fn save_credential(
        &self,
        data: &Self::CredentialEntityAccessor,
    ) -> Result<(), CredentialError> {
        let credential_bytes: Vec<u8> = data.to_owned().try_into().map_err(|_| {
            CredentialError::CommonError(VerifiableError::RepoError(
                "unable to convert credential to bytes".to_string(),
            ))
        })?;

        let credential_id_key = self.build_credential_id_key(data.get_id());
        let credential_did_merge_key = self.build_credential_merge_did_key(data.get_did_issuer());

        let _ = self
            .db
            .exec(DbInstruction::SaveCf {
                key: credential_id_key,
                value: credential_bytes.clone(),
            })
            .await
            .map_err(|err| {
                CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        // before we're able to merge some values, we need to make sure that given bucket already exists or not
        let check_bucket_exists = self
            .check_merge_credential_did_exists(credential_did_merge_key.clone())
            .await;

        match check_bucket_exists {
            true => {
                let _ = self
                    .db
                    .exec(DbInstruction::MergeCf {
                        key: credential_did_merge_key.clone(),
                        value: credential_bytes.clone(),
                    })
                    .await
                    .map_err(|err| {
                        CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
                    })?;
            }
            false => {
                let mut bucket = DbBucket::<Credential>::new();
                bucket.add(data.to_owned());

                let bucket_bytes: Vec<u8> = bucket
                    .try_into()
                    .map_err(|err: DbError| CredentialError::GenerateJSONError(err.to_string()))?;

                let _ = self
                    .db
                    .exec(DbInstruction::SaveCf {
                        key: credential_did_merge_key.clone(),
                        value: bucket_bytes,
                    })
                    .await
                    .map_err(|err| {
                        CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
                    })?;
            }
        }

        Ok(())
    }

    async fn save_credential_holder(
        &self,
        data: &Self::HolderEntityAccessor,
    ) -> Result<(), CredentialError> {
        let holder_bytes: Vec<u8> = data.to_owned().try_into().map_err(|_| {
            CredentialError::CommonError(VerifiableError::RepoError(
                "unable to convert holder to bytes".to_string(),
            ))
        })?;

        let holder_key = self.build_holder_key(data.get_id());

        let _ = self
            .db
            .exec(DbInstruction::SaveCf {
                key: holder_key,
                value: holder_bytes,
            })
            .await
            .map_err(|err| {
                CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        Ok(())
    }

    async fn set_credential_holder_verified(
        &self,
        holder: &Self::HolderEntityAccessor,
    ) -> Result<(), CredentialError> {
        self.save_credential_holder(holder).await
    }

    async fn remove_credential_by_id(&self, id: String) -> Result<(), CredentialError> {
        let credential_key = self.build_credential_id_key(id);
        let _ = self
            .db
            .exec(DbInstruction::RemoveCf {
                key: credential_key,
            })
            .await
            .map_err(|err| {
                CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        Ok(())
    }

    async fn get_credential_by_id(
        &self,
        id: String,
    ) -> Result<Self::CredentialEntityAccessor, CredentialError> {
        let credential_key = self.build_credential_id_key(id);

        let value_cred = self
            .db
            .exec(DbInstruction::GetCf {
                key: credential_key,
            })
            .await
            .map_err(|err| {
                CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        let credential = {
            match value_cred {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            Credential::try_from(val)
                                .map_err(|err| CredentialError::UnserializeError(err.to_string()))
                        })
                        .ok_or(CredentialError::CredentialNotFound)??;

                    Ok(output)
                }
                _ => Err(CredentialError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        }?;

        Ok(credential)
    }

    async fn get_holder_by_id(
        &self,
        id: String,
    ) -> Result<Self::HolderEntityAccessor, CredentialError> {
        let holder_key = self.build_holder_key(id);

        let value_holder = self
            .db
            .exec(DbInstruction::GetCf { key: holder_key })
            .await
            .map_err(|err| {
                CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        let holder = {
            match value_holder {
                DbOutput::SingleByte { value } => {
                    let holder_output =
                        value
                            .map(|val| val)
                            .ok_or(CredentialError::UnserializeError(
                                "unable to unserialize db output".to_string(),
                            ))?;

                    let holder = Holder::try_from(holder_output)
                        .map_err(|err| CredentialError::UnserializeError(err.to_string()));

                    holder
                }
                _ => Err(CredentialError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        }?;

        Ok(holder)
    }

    async fn list_credentials_by_ids(
        &self,
        ids: Vec<String>,
    ) -> Result<Vec<Self::CredentialEntityAccessor>, CredentialError> {
        let credential_keys = ids
            .iter()
            .map(|val| self.build_credential_id_key(val.to_owned()));

        let values = self
            .db
            .exec(DbInstruction::MultiGetCf {
                keys: credential_keys.collect(),
            })
            .await
            .map_err(|err| {
                CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        let credentials = {
            match values {
                DbOutput::MultiBytes { values } => {
                    let mut creds: Vec<Credential> = Vec::new();

                    let _ = values
                        .iter()
                        .map(|val| {
                            let cred_val = val.as_ref().map_or(None, |val| {
                                let cred_val_bytes = val
                                    .clone()
                                    .map(|val| {
                                        let cred = Credential::try_from(val)
                                            .map_err(|err| {
                                                CredentialError::CommonError(
                                                    VerifiableError::RepoError(err.to_string()),
                                                )
                                            })
                                            .map_or(None, |cred| Some(cred));

                                        cred
                                    })
                                    .flatten();

                                cred_val_bytes
                            });

                            cred_val
                        })
                        .for_each(|val| {
                            val.map(|cred| creds.push(cred));
                        });

                    Ok(creds)
                }
                _ => Err(CredentialError::UnserializeError(
                    "unknown output bytes".to_string(),
                )),
            }
        }?;

        Ok(credentials)
    }

    async fn list_credentials_by_did(
        &self,
        did: String,
        _pagination: Option<PaginationParams>,
    ) -> Result<Vec<Self::CredentialEntityAccessor>, CredentialError> {
        let credential_merge_key = self.build_credential_merge_did_key(did);

        let value_cred = self
            .db
            .exec(DbInstruction::GetCf {
                key: credential_merge_key,
            })
            .await
            .map_err(|err| {
                CredentialError::CommonError(VerifiableError::RepoError(err.to_string()))
            })?;

        let credential = {
            match value_cred {
                DbOutput::SingleByte { value } => {
                    let output = value
                        .map(|val| {
                            let bucket: Result<DbBucket<Credential>, DbError> = val.try_into();
                            bucket
                        })
                        .ok_or(CredentialError::CredentialNotFound)?
                        .map_err(|err| CredentialError::ListError(err.to_string()))?;

                    Ok(output)
                }
                _ => Err(CredentialError::UnserializeError(
                    "unknown output type".to_string(),
                )),
            }
        }?;

        let mut output: Vec<Credential> = Vec::new();
        for cred in credential.iterate() {
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
    use rst_common::standard::serde_json;
    use rst_common::with_tokio::tokio;

    use prople_crypto::keysecure::types::{ToKeySecure, Password};

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;
    use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
    use prople_did_core::verifiable::objects::VC;

    use prople_vessel_core::identity::account::Account as AccountIdentity;
    use prople_vessel_core::identity::verifiable::proof::builder::Builder as ProofBuilder;

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
            .to_keysecure(Password::from("password".to_string()))
            .unwrap();

        AccountIdentity::new(
            did_vc_value_cloned.clone(),
            did_vc_doc,
            did_vc_doc_private_keys,
            did_vc_keysecure,
        )
    }

    async fn generate_credential() -> Credential {
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
        )
        .await;

        credential_builder.unwrap()
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
        )
        .unwrap()
        .unwrap();

        vc.proof(proof_builder);
        let holder = Holder::new(did_value, vc);

        (holder, did_doc)
    }

    async fn generate_credetial_custom_did_issuer(did_issuer_value: String) -> Credential {
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
        )
        .await;

        credential_builder.unwrap()
    }

    #[tokio::test]
    async fn test_save_get() {
        let credential = generate_credential().await;
        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);

        let try_save = repo.save_credential(&credential).await;
        assert!(!try_save.is_err());

        let cred_value = repo.get_credential_by_id(credential.get_id()).await;
        assert!(!cred_value.is_err());

        let cred_from_db = cred_value.unwrap();
        assert_eq!(cred_from_db.get_did_vc(), credential.get_did_vc())
    }

    #[tokio::test]
    async fn test_save_get_holder() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let (holder, _) = generate_holder(addr, "password".to_string());

        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);

        let try_save = repo.save_credential_holder(&holder).await;
        assert!(!try_save.is_err());

        let holder_value = repo.get_holder_by_id(holder.get_id()).await;
        assert!(!holder_value.is_err());
        assert_eq!(holder_value.unwrap().get_id(), holder.get_id())
    }

    #[tokio::test]
    async fn test_save_update_holder() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let (mut holder, _) = generate_holder(addr, "password".to_string());

        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);

        let try_save = repo.save_credential_holder(&holder).await;
        assert!(!try_save.is_err());

        let holder_updated = holder.set_verified();
        let try_update = repo.set_credential_holder_verified(holder_updated).await;
        assert!(!try_update.is_err());

        let holder_value = repo.get_holder_by_id(holder.get_id()).await;
        assert!(!holder_value.is_err());

        let holder_from_db = holder_value.unwrap();
        assert!(holder_from_db.get_is_verified());
        assert_eq!(holder.get_id(), holder_from_db.get_id())
    }

    #[tokio::test]
    async fn test_save_remove_get() {
        let credential = generate_credential().await;
        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);

        let try_save = repo.save_credential(&credential).await;
        assert!(!try_save.is_err());

        let try_remove = repo.remove_credential_by_id(credential.get_id()).await;
        assert!(!try_remove.is_err());

        let cred_value = repo.get_credential_by_id(credential.get_id()).await;
        assert!(cred_value.is_err());
        assert!(matches!(
            cred_value.unwrap_err(),
            CredentialError::CredentialNotFound
        ))
    }

    #[tokio::test]
    async fn test_save_many_credetials_list() {
        let credential1 = generate_credential().await;
        let credential2 = generate_credential().await;
        let credential3 = generate_credential().await;

        let credential_ids = vec![
            credential1.get_id(),
            credential2.get_id(),
            credential3.get_id(),
        ];
        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);

        let try_save1 = repo.save_credential(&credential1).await;
        assert!(!try_save1.is_err());

        let try_save2 = repo.save_credential(&credential2).await;
        assert!(!try_save2.is_err());

        let try_save3 = repo.save_credential(&credential3).await;
        assert!(!try_save3.is_err());

        let credentials_finder = repo.list_credentials_by_ids(credential_ids.clone()).await;
        assert!(!credentials_finder.is_err());

        let credentials_from_db = credentials_finder.unwrap();
        assert_eq!(credentials_from_db.len(), 3);

        let credential_ids_slice = credential_ids.as_slice();
        for cred in credentials_from_db.iter() {
            assert!(credential_ids_slice.contains(&cred.get_id()))
        }
    }

    #[tokio::test]
    async fn test_credentials_partial_not_found() {
        let credential1 = generate_credential().await;
        let credential2 = generate_credential().await;
        let credential3 = generate_credential().await;

        let credential_ids = vec![
            credential1.get_id(),
            credential2.get_id(),
            credential3.get_id(),
            "unknown id".to_string(),
        ];
        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);

        let try_save1 = repo.save_credential(&credential1).await;
        assert!(!try_save1.is_err());

        let try_save2 = repo.save_credential(&credential2).await;
        assert!(!try_save2.is_err());

        let try_save3 = repo.save_credential(&credential3).await;
        assert!(!try_save3.is_err());

        let credentials_finder = repo.list_credentials_by_ids(credential_ids.clone()).await;
        assert!(!credentials_finder.is_err());

        let credentials_from_db = credentials_finder.unwrap();
        assert_eq!(credentials_from_db.len(), 3);
    }

    #[tokio::test]
    async fn test_save_merge_list_credentials() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let credential1 = generate_credetial_custom_did_issuer(did_issuer_value.clone()).await;
        let credential2 = generate_credetial_custom_did_issuer(did_issuer_value.clone()).await;
        let credential3 = generate_credetial_custom_did_issuer(did_issuer_value.clone()).await;

        let db_builder = testdb::global_db_builder().to_owned();
        let repo = Repository::new(db_builder);

        let try_save1 = repo.save_credential(&credential1).await;
        assert!(!try_save1.is_err());

        let try_save2 = repo.save_credential(&credential2).await;
        assert!(!try_save2.is_err());

        let try_save3 = repo.save_credential(&credential3).await;
        assert!(!try_save3.is_err());

        let credentials_finder = repo.list_credentials_by_did(did_issuer_value, None).await;
        assert!(!credentials_finder.is_err());

        let credentials = credentials_finder.unwrap();
        assert_eq!(credentials.len(), 3)
    }
}
