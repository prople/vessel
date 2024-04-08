use prople_crypto::keysecure::types::ToKeySecure;
use prople_did_core::did::DID;

use crate::ssi::account::types::{
    Account, AccountError, AccountRepositoryBuilder, AccountUsecaseBuilder,
};

/// `Usecase` is base logic implementation for the [`AccountUsecaseBuilder`]
///
/// This object depends on the implementation of [`AccountRepositoryBuilder`]
pub struct Usecase<TRepo>
where
    TRepo: AccountRepositoryBuilder,
{
    repo: TRepo,
}

impl<TRepo> Usecase<TRepo>
where
    TRepo: AccountRepositoryBuilder,
{
    pub fn new(repo: TRepo) -> Self {
        Self { repo }
    }
}

impl<TRepo> AccountUsecaseBuilder for Usecase<TRepo>
where
    TRepo: AccountRepositoryBuilder,
{
    fn generate_did(&self, password: String) -> Result<Account, AccountError> {
        let did = DID::new();
        let identity = did
            .identity()
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        let account_keysecure = did
            .account()
            .privkey()
            .to_keysecure(password)
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        let account = Account::new(identity.value(), account_keysecure);

        let _ = self
            .repo
            .save(&account)
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        Ok(account)
    }

    fn remove_did(&self, did: String) -> Result<(), AccountError> {
        self.repo.remove_by_did(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;

    mock!(
        FakeRepo{}

        impl AccountRepositoryBuilder for FakeRepo {
            fn save(&self, account: &Account) -> Result<(), AccountError>;
            fn remove_by_did(&self, did: String) -> Result<(), AccountError>;
        }
    );

    fn generate_usecase<TRepo: AccountRepositoryBuilder>(repo: TRepo) -> Usecase<TRepo> {
        Usecase::new(repo)
    }

    #[test]
    fn test_storage_repo_success() {
        let mut repo = MockFakeRepo::new();
        repo.expect_save().returning(|_| Ok(()));

        let uc = generate_usecase(repo);
        let output = uc.generate_did("password".to_string());
        assert!(!output.is_err());

        let acc = output.unwrap();
        assert!(!acc.id.is_empty());
        assert!(!acc.did.is_empty());
        assert!(!acc.keysecure.to_json().is_err());
        assert!(!acc.created_at.to_rfc3339().is_empty());
    }

    #[test]
    fn test_storage_repo_failed() {
        let mut repo = MockFakeRepo::new();
        repo.expect_save().returning(|_| {
            Err(AccountError::GenerateIdentityError(
                "error fake repo".to_string(),
            ))
        });

        let uc = generate_usecase(repo);
        let output = uc.generate_did("password".to_string());
        assert!(output.is_err());
        assert!(matches!(
            output.unwrap_err(),
            AccountError::GenerateIdentityError(_)
        ))
    }
}
