use rst_common::standard::async_trait::async_trait;
use rstdev_storage::engine::rocksdb::db::DB;

use prople_vessel_core::identity::verifiable::credential::types::{
    CredentialEntityAccessor, CredentialError, HolderEntityAccessor, RepoBuilder,
};
use prople_vessel_core::identity::verifiable::types::{PaginationParams, VerifiableError};
use prople_vessel_core::identity::verifiable::{Credential, Holder};

use crate::apps::{DbInstruction, DbOutput, DbRunner};

const CREDENTIAL_KEY_ID: &str = "credential_id";
const CREDENTIAL_KEY_DID: &str = "credential_did";
const HOLDER_KEY_ID: &str = "holder_id";

#[derive(Clone)]
pub struct Repository {
    db: DbRunner<DB>,
}

#[allow(dead_code)]
impl Repository {
    pub fn new(db: DbRunner<DB>) -> Self {
        Self { db }
    }

    fn build_credential_id_key(&self, val: String) -> String {
        format!("{}:{}", CREDENTIAL_KEY_ID.to_string(), val)
    }

    fn build_credential_did_key(&self, val: String) -> String {
        format!("{}:{}", CREDENTIAL_KEY_DID.to_string(), val)
    }

    fn build_holder_key(&self, val: String) -> String {
        format!("{}:{}", HOLDER_KEY_ID.to_string(), val)
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
        _did: String,
        _pagination: Option<PaginationParams>,
    ) -> Result<Vec<Self::CredentialEntityAccessor>, CredentialError> {
        Err(CredentialError::CommonError(VerifiableError::RepoError(
            "not implemented".to_string(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::helpers::testdb;

    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::standard::serde_json;
    use rst_common::with_tokio::tokio;

    use prople_crypto::keysecure::types::ToKeySecure;

    use prople_did_core::did::DID;
    use prople_did_core::doc::types::ToDoc;
    use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;

    use prople_vessel_core::identity::account::Account as AccountIdentity;

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

        AccountIdentity::new(
            did_vc_value_cloned.clone(),
            "did-uri".to_string(),
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
            None,
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
}
