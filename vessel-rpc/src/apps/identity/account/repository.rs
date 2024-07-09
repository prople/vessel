use std::convert::TryInto;

use rst_common::standard::async_trait::async_trait;
use rstdev_storage::engine::rocksdb::db::DB;

use prople_vessel_core::identity::account::types::{
    AccountEntityAccessor, AccountError, RepoBuilder,
};
use prople_vessel_core::identity::account::Account;

use crate::apps::types::AppError;
use crate::apps::{DbInstruction, DbRunner};

const ACCOUNT_KEY_ID: &str = "account_id";
const ACCOUNT_KEY_DID: &str = "account_did";

#[derive(Clone)]
pub struct Repository {
    db: DbRunner<DB>,
}

#[allow(dead_code)]
impl Repository {
    pub fn new(db: DbRunner<DB>) -> Self {
        Self { db }
    }

    fn build_account_keys(&self, account: Account) -> (String, String) {
        (
            self.build_account_key(ACCOUNT_KEY_ID.to_string(), account.get_id()),
            self.build_account_key(ACCOUNT_KEY_DID.to_string(), account.get_did()),
        )
    }

    fn build_account_key(&self, prefix: String, val: String) -> String {
        format!("{}:{}", prefix, val)
    }

    async fn get_id_by_did(&self, did: String) -> Result<String, AppError> {
        let account_key_did = self.build_account_key(ACCOUNT_KEY_DID.to_string(), did);

        let value_id = self
            .db
            .exec(DbInstruction::GetCf {
                key: account_key_did.clone(),
            })
            .await
            .map_err(|err| AppError::DbError(err.to_string()))?
            .map(|val| val)
            .ok_or(AppError::DbError("did not found".to_string()))?;

        let str_id =
            String::from_utf8(value_id).map_err(|err| AppError::DbError(err.to_string()))?;

        Ok(str_id)
    }
}

#[async_trait]
impl RepoBuilder for Repository {
    type EntityAccessor = Account;

    async fn save_account(&self, account: &Self::EntityAccessor) -> Result<(), AccountError> {
        let account_bytes: Vec<u8> = account.to_owned().try_into().map_err(|_| {
            AccountError::SaveAccountError("unable to convert account to bytes".to_string())
        })?;

        let (key_id, key_did) = self.build_account_keys(account.clone());

        let _ = self
            .db
            .exec(DbInstruction::SaveCf {
                key: key_id,
                value: account_bytes,
            })
            .await
            .map_err(|err| AccountError::SaveAccountError(err.to_string()))?;

        let _ = self
            .db
            .exec(DbInstruction::SaveCf {
                key: key_did,
                value: account.get_id().into_bytes(),
            })
            .await
            .map_err(|err| AccountError::SaveAccountError(err.to_string()))?;

        Ok(())
    }

    async fn remove_account_by_did(&self, did: String) -> Result<(), AccountError> {
        let str_id = self
            .get_id_by_did(did.clone())
            .await
            .map_err(|err| AccountError::UnknownError(err.to_string()))?;

        let account_key_did = self.build_account_key(ACCOUNT_KEY_DID.to_string(), did);
        let account_key_id = self.build_account_key(ACCOUNT_KEY_ID.to_string(), str_id);

        let _ = self
            .db
            .exec(DbInstruction::RemoveCf {
                key: account_key_did,
            })
            .await
            .map_err(|err| AccountError::SaveAccountError(err.to_string()))?;

        let _ = self
            .db
            .exec(DbInstruction::RemoveCf {
                key: account_key_id,
            })
            .await
            .map_err(|err| AccountError::SaveAccountError(err.to_string()))?;

        Ok(())
    }

    async fn get_account_by_did(&self, did: String) -> Result<Self::EntityAccessor, AccountError> {
        let str_id = self
            .get_id_by_did(did.clone())
            .await
            .map_err(|err| AccountError::UnknownError(err.to_string()))?;

        let account_key_id = self.build_account_key(ACCOUNT_KEY_ID.to_string(), str_id);
        let value_account = self
            .db
            .exec(DbInstruction::GetCf {
                key: account_key_id,
            })
            .await
            .map_err(|err| AccountError::UnknownError(err.to_string()))?
            .map(|val| val)
            .ok_or(AccountError::DIDNotFound)?;

        let account = Account::try_from(value_account)
            .map_err(|err| AccountError::UnknownError(err.to_string()))?;

        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::helpers::testdb;
    use rst_common::with_tokio::tokio;

    #[tokio::test]
    async fn test_save_get() {
        let db_builder = testdb::global_db_builder().to_owned();
        let account_builder = Account::generate("password".to_string(), None);
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();
        let repo = Repository::new(db_builder);

        let try_save = repo.save_account(&account).await;
        assert!(!try_save.is_err());

        let account_value = repo.get_account_by_did(account.get_did()).await;
        assert!(!account_value.is_err());

        let account_from_db = account_value.unwrap();
        assert_eq!(account_from_db.get_did(), account.get_did())
    }

    #[tokio::test]
    async fn test_save_remove_get() {
        let db_builder = testdb::global_db_builder().to_owned();
        let account_builder = Account::generate("password".to_string(), None);
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();
        let repo = Repository::new(db_builder);

        let try_save = repo.save_account(&account).await;
        assert!(!try_save.is_err());

        let try_remove = repo.remove_account_by_did(account.get_did()).await;
        assert!(!try_remove.is_err());

        let account_value = repo.get_account_by_did(account.get_did()).await;
        assert!(account_value.is_err());
        assert!(matches!(
            account_value.unwrap_err(),
            AccountError::UnknownError(_)
        ))
    }
}
