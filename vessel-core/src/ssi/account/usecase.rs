use prople_crypto::keysecure::types::ToKeySecure;

use prople_did_core::did::{IdentityPayload, DID};
use prople_did_core::identity::payload::account::Account as IdentityPayloadAccount;
use prople_did_core::identity::payload::resolver::Resolver as IdentityPayloadResolver;
use prople_did_core::identity::payload::resolver::{
    Address as IdentityPayloadAddress, AddressType as IdentityPayloadAddressType,
};
use prople_did_core::identity::payload::Payload as IdentityPayloadCore;

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
    fn generate_did(&self, address: String, password: String) -> Result<Account, AccountError> {
        let identity_payload_account = IdentityPayloadAccount::new();
        let identity_payload_addr =
            IdentityPayloadAddress::new(IdentityPayloadAddressType::Peer, address);
        let identity_payload_resolver = IdentityPayloadResolver::new(identity_payload_addr);
        let identity_payload_core =
            IdentityPayloadCore::new(identity_payload_account.clone(), identity_payload_resolver);
        let identity_payload = IdentityPayload::new(identity_payload_core)
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        let did = DID::new(identity_payload);
        let identity = did
            .identity()
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        let account_payload =
            identity_payload_account
                .account
                .ok_or(AccountError::GenerateIdentityError(
                    "unable to generate account".to_string(),
                ))?;

        let account_keysecure = account_payload
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;

    mock!(
        FakeRepo{}

        impl AccountRepositoryBuilder for FakeRepo {
            fn save(&self, account: &Account) -> Result<(), AccountError>;
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
        let output = uc.generate_did("addr".to_string(), "password".to_string());
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
        let output = uc.generate_did("addr".to_string(), "password".to_string());
        assert!(output.is_err());
        assert!(matches!(output.unwrap_err(), AccountError::GenerateIdentityError(_)))
    }
}
