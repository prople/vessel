use rst_common::standard::async_trait::async_trait;
use std::convert::TryInto;

use rstdev_storage::engine::rocksdb::db::DB;

use prople_vessel_core::identity::account::types::{
    AccountEntityAccessor, AccountError, RepoBuilder,
};
use prople_vessel_core::identity::account::Account;

use crate::apps::DbBuilder;

#[derive(Clone)]
pub struct Repository {
    db: DbBuilder<DB>,
}

#[allow(dead_code)]
impl Repository {
    pub fn new(db: DbBuilder<DB>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl RepoBuilder for Repository {
    type EntityAccessor = Account;

    async fn save_account(&self, account: &Self::EntityAccessor) -> Result<(), AccountError> {
        let db_instance = self
            .db
            .clone()
            .instance
            .map(|val| val.db)
            .ok_or(AccountError::SaveAccountError(
                "db instance is missing".to_string(),
            ))?
            .map(|db| db)
            .ok_or(AccountError::SaveAccountError(
                "rocksdb instance is missing".to_string(),
            ))?
            .clone();

        let cf = db_instance
            .cf_handle(self.db.get_cf(|db| db.identity.get_common()).as_str())
            .map(|val| val)
            .ok_or(AccountError::SaveAccountError(
                "cf handler failed".to_string(),
            ))?;

        let account_bytes: Vec<u8> = account.to_owned().try_into().map_err(|_| {
            AccountError::SaveAccountError("unable to convert account to bytes".to_string())
        })?;

        let _ = db_instance
            .put_cf(cf, account.to_owned().get_did(), account_bytes)
            .map_err(|err| AccountError::SaveAccountError(err.to_string()))?;

        Ok(())
    }

    async fn remove_account_by_did(&self, did: String) -> Result<(), AccountError> {
        let db_instance = self
            .db
            .clone()
            .instance
            .map(|val| val.db)
            .ok_or(AccountError::SaveAccountError(
                "db instance is missing".to_string(),
            ))?
            .map(|db| db)
            .ok_or(AccountError::SaveAccountError(
                "rocksdb instance is missing".to_string(),
            ))?
            .clone();

        let cf = db_instance
            .cf_handle(self.db.get_cf(|db| db.identity.get_common()).as_str())
            .map(|val| val)
            .ok_or(AccountError::SaveAccountError(
                "cf handler failed".to_string(),
            ))?;

        let _ = db_instance
            .delete_cf(cf, did)
            .map_err(|err| AccountError::RemoveDIDError(err.to_string()))?;

        Ok(())
    }

    async fn get_account_by_did(&self, did: String) -> Result<Self::EntityAccessor, AccountError> {
        let db_instance = self
            .db
            .clone()
            .instance
            .map(|val| val.db)
            .ok_or(AccountError::SaveAccountError(
                "db instance is missing".to_string(),
            ))?
            .map(|db| db)
            .ok_or(AccountError::SaveAccountError(
                "rocksdb instance is missing".to_string(),
            ))?
            .clone();

        let cf = db_instance
            .cf_handle(self.db.get_cf(|db| db.identity.get_common()).as_str())
            .map(|val| val)
            .ok_or(AccountError::SaveAccountError(
                "cf handler failed".to_string(),
            ))?;

        let value = db_instance
            .get_cf(cf, did)
            .map_err(|err| AccountError::UnknownError(err.to_string()))?
            .map(|val| val)
            .ok_or(AccountError::DIDNotFound)?;

        let account = Account::try_from(value)
            .map_err(|err| AccountError::UnknownError(err.to_string()))?;

        Ok(account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use rst_common::with_tokio::tokio;
    use crate::common::helpers::testdb;

    #[tokio::test]
    async fn test_save_get() {
        let db_builder = testdb::global_db_builder().to_owned();
        let account_builder= Account::generate("password".to_string(), None);
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
        let account_builder= Account::generate("password".to_string(), None);
        assert!(!account_builder.is_err());

        let account = account_builder.unwrap();
        let repo = Repository::new(db_builder);
        
        let try_save = repo.save_account(&account).await;
        assert!(!try_save.is_err());

        let try_remove = repo.remove_account_by_did(account.get_did()).await;
        assert!(!try_remove.is_err());
        
        let account_value = repo.get_account_by_did(account.get_did()).await;
        assert!(account_value.is_err());
        assert!(matches!(account_value.unwrap_err(), AccountError::DIDNotFound))
    }
}