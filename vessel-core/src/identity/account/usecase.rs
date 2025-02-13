use rst_common::standard::async_trait::async_trait;

use prople_did_core::did::query::Params;
use prople_did_core::doc::types::Doc;
use prople_did_core::hashlink::{self, verify_from_json};

use super::types::{
    AccountAPI, AccountEntityAccessor, AccountError, RepoBuilder, RpcBuilder, UsecaseBuilder,
};

use super::Account;
use super::URI;

#[derive(Clone)]
/// `Usecase` is base logic implementation for the [`AccountUsecaseBuilder`]
///
/// This object depends on the implementation of [`AccountRepositoryBuilder`]
pub struct Usecase<TRepo, TRPCClient>
where
    TRepo: RepoBuilder<EntityAccessor = Account>,
    TRPCClient: RpcBuilder,
{
    repo: TRepo,
    rpc: TRPCClient,
}

impl<TRepo, TRPCClient> Usecase<TRepo, TRPCClient>
where
    TRepo: RepoBuilder<EntityAccessor = Account>,
    TRPCClient: RpcBuilder,
{
    pub fn new(repo: TRepo, rpc: TRPCClient) -> Self {
        Self { repo, rpc }
    }
}

#[async_trait]
impl<TRepo, TRPCClient> UsecaseBuilder<Account> for Usecase<TRepo, TRPCClient>
where
    TRepo: RepoBuilder<EntityAccessor = Account>,
    TRPCClient: RpcBuilder + Send + Sync,
{
    type RepoImplementer = TRepo;
    type RPCImplementer = TRPCClient;

    fn repo(&self) -> Self::RepoImplementer {
        self.repo.clone()
    }

    fn rpc(&self) -> Self::RPCImplementer {
        self.rpc.clone()
    }
}

#[async_trait]
impl<TRepo, TRPCClient> AccountAPI for Usecase<TRepo, TRPCClient>
where
    TRepo: RepoBuilder<EntityAccessor = Account>,
    TRPCClient: RpcBuilder + Send + Sync,
{
    type EntityAccessor = Account;

    async fn generate_did(&self, password: String) -> Result<Account, AccountError> {
        let account = Account::generate(password)?;
        let _ = self
            .repo()
            .save_account(&account)
            .await
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        Ok(account)
    }

    async fn build_did_uri(
        &self,
        did: String,
        password: String,
        params: Option<Params>,
    ) -> Result<String, AccountError> {
        let account = self
            .repo()
            .get_account_by_did(did)
            .await
            .map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        let hl_doc = hashlink::generate_from_json(account.get_doc())
            .map_err(|err| AccountError::BuildURIError(err.to_string()))?;

        let mut query_params = Params::default();
        query_params.hl = Some(hl_doc);
        query_params.address = params.map(|val| val.address).flatten();

        URI::build(account, password, Some(query_params))
    }

    async fn resolve_did_uri(&self, uri: String) -> Result<Doc, AccountError> {
        let (uri_addr, uri_params, uri_did) = URI::parse(uri)?;
        if uri_params.hl.is_none() {
            return Err(AccountError::RemoveDIDError(
                "missing hashlink parameter".to_string(),
            ));
        }

        if uri_addr.is_none() {
            return Err(AccountError::ResolveDIDError(
                "misisng uri addres".to_string(),
            ));
        }

        let doc = self
            .rpc()
            .resolve_did_doc(uri_addr.unwrap(), uri_did)
            .await?;
        verify_from_json(doc.clone(), uri_params.hl.unwrap())
            .map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        Ok(doc)
    }

    async fn resolve_did_doc(&self, did: String) -> Result<Doc, AccountError> {
        let account = self.repo().get_account_by_did(did).await?;
        Ok(account.get_doc())
    }

    async fn remove_did(&self, did: String) -> Result<(), AccountError> {
        self.repo().remove_account_by_did(did).await
    }

    async fn get_account_did(&self, did: String) -> Result<Account, AccountError> {
        self.repo().get_account_by_did(did).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use multiaddr::{multiaddr, Multiaddr};
    use rst_common::with_tokio::tokio;

    use prople_crypto::keysecure::types::{Password, ToKeySecure};

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::hashlink::generate_from_json;
    use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;
    use prople_did_core::types::ToJSON;

    use super::Account;

    mock!(
        FakeRepo{}

        impl Clone for FakeRepo {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RepoBuilder for FakeRepo {
            type EntityAccessor = Account;
            async fn save_account(&self, account: &Account) -> Result<(), AccountError>;
            async fn remove_account_by_did(&self, did: String) -> Result<(), AccountError>;
            async fn get_account_by_did(&self, did: String) -> Result<Account, AccountError>;
        }
    );

    mock!(
        FakeRPCClient{}

        impl Clone for FakeRPCClient {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RpcBuilder for FakeRPCClient {
            async fn resolve_did_doc(&self, addr: Multiaddr, did: String) -> Result<Doc, AccountError>;
        }
    );

    fn generate_usecase<TRepo: RepoBuilder<EntityAccessor = Account>, TRPCClient: RpcBuilder>(
        repo: TRepo,
        rpc: TRPCClient,
    ) -> Usecase<TRepo, TRPCClient> {
        Usecase::new(repo, rpc)
    }

    #[tokio::test]
    async fn test_storage_repo_success() {
        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save_account().returning(|_| Ok(()));

            expected
        });

        let rpc = MockFakeRPCClient::new();

        let uc = generate_usecase(repo, rpc);
        let output = uc.generate_did("password".to_string()).await;
        assert!(!output.is_err());

        let acc = output.unwrap();
        assert!(!acc.id.is_empty());
        assert!(!acc.did.is_empty());
        assert!(!acc.keysecure.to_json().is_err());
        assert!(!acc.created_at.to_rfc3339().is_empty());
    }

    #[tokio::test]
    async fn test_storage_repo_failed() {
        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save_account().returning(|_| {
                Err(AccountError::GenerateIdentityError(
                    "error fake repo".to_string(),
                ))
            });

            expected
        });

        let rpc = MockFakeRPCClient::new();

        let uc = generate_usecase(repo, rpc);
        let output = uc.generate_did("password".to_string()).await;
        assert!(output.is_err());
        assert!(matches!(
            output.unwrap_err(),
            AccountError::GenerateIdentityError(_)
        ))
    }

    #[tokio::test]
    async fn test_build_did_uri_without_params() {
        let did = DID::new();
        let identity = did.identity().unwrap();

        let identity_value = identity.value();
        let identity_doc = identity.to_doc();
        let identity_doc_private_keys =
            identity.build_private_keys("password".to_string()).unwrap();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save_account().returning(|_| Ok(()));
            expected.expect_get_account_by_did().returning(move |_| {
                let keysecure = did
                    .account()
                    .privkey()
                    .to_keysecure(Password::from("password".to_string()))
                    .unwrap();

                let account = Account::new(
                    identity_value.clone(),
                    identity_doc.clone(),
                    identity_doc_private_keys.clone(),
                    keysecure,
                );
                Ok(account)
            });

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc);
        let uri = uc
            .build_did_uri(identity.clone().value(), "password".to_string(), None)
            .await;

        assert!(!uri.is_err());
    }

    #[tokio::test]
    async fn test_build_did_uri_with_params() {
        let did = DID::new();
        let identity = did.identity().unwrap();

        let identity_value = identity.value();
        let identity_doc = identity.to_doc();
        let identity_doc_private_keys =
            identity.build_private_keys("password".to_string()).unwrap();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save_account().returning(|_| Ok(()));
            expected.expect_get_account_by_did().returning(move |_| {
                let keysecure = did
                    .account()
                    .privkey()
                    .to_keysecure(Password::from("password".to_string()))
                    .unwrap();
                let account = Account::new(
                    identity_value.clone(),
                    identity_doc.clone(),
                    identity_doc_private_keys.clone(),
                    keysecure,
                );
                Ok(account)
            });

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc);

        let doc = identity.clone().to_doc();
        let doc_hl_result = generate_from_json(doc);
        assert!(!doc_hl_result.is_err());

        let doc_hl = doc_hl_result.unwrap();
        let params = Params {
            address: Some("test-addr".to_string()),
            hl: Some(doc_hl.clone()),
        };

        let uri = uc
            .build_did_uri(
                identity.clone().value(),
                "password".to_string(),
                Some(params),
            )
            .await;
        assert!(!uri.is_err());

        let uri_expected = format!(
            "{}?address=test-addr&hl={}",
            identity.clone().value(),
            doc_hl
        );
        assert_eq!(uri.unwrap(), uri_expected)
    }

    #[tokio::test]
    async fn test_resolve_did_uri_success() {
        let did = DID::new();
        let did_cloned = did.clone();
        let identity = did.identity().unwrap();

        let identity_repo_clone = identity.clone();
        let identity_repo_clone_doc = identity.clone().to_doc();
        let identity_repo_clone_doc_private_keys = identity
            .clone()
            .build_private_keys("password".to_string())
            .unwrap();

        let identity_clone = identity.clone();
        let identity_clone_doc = identity.clone().to_doc();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().returning(move || {
            let did = did_cloned.clone();
            let identity_repo_clone = identity_repo_clone.clone();
            let identity_repo_clone_doc = identity_repo_clone_doc.clone();
            let identity_repo_clone_doc_private_keys = identity_repo_clone_doc_private_keys.clone();

            let mut expected = MockFakeRepo::new();
            expected.expect_save_account().returning(|_| Ok(()));
            expected.expect_get_account_by_did().returning(move |_| {
                let keysecure = did
                    .account()
                    .privkey()
                    .to_keysecure(Password::from("password".to_string()))
                    .unwrap();
                let account = Account::new(
                    identity_repo_clone.clone().value(),
                    identity_repo_clone_doc.clone(),
                    identity_repo_clone_doc_private_keys.clone(),
                    keysecure,
                );
                Ok(account)
            });

            expected
        });

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRPCClient::new();
            expected
                .expect_resolve_did_doc()
                .times(1)
                .withf(move |addr: &Multiaddr, did: &String| {
                    let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
                    addr == &input_addr && did == &identity_clone.value()
                })
                .returning(move |_, _| Ok(identity_clone_doc.clone()));

            expected
        });

        let uc = generate_usecase(repo, rpc);
        let account = uc.generate_did("password".to_string()).await;
        assert!(!account.is_err());

        let doc_hl_result = generate_from_json(identity.clone().to_doc());
        assert!(!doc_hl_result.is_err());

        let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
        let params = Params {
            address: Some(input_addr.to_string()),
            hl: Some(doc_hl_result.unwrap()),
        };

        let uri = uc
            .build_did_uri(
                identity.clone().value(),
                "password".to_string(),
                Some(params),
            )
            .await;
        assert!(!uri.is_err());

        let resolved = uc.resolve_did_uri(uri.unwrap()).await;
        assert!(!resolved.is_err());
        assert_eq!(
            resolved.unwrap().to_json().unwrap().to_bytes(),
            identity.to_doc().to_json().unwrap().to_bytes()
        )
    }

    #[tokio::test]
    async fn test_resolve_did_uri_failed_missing_hl() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();

        let uc = generate_usecase(repo, rpc);

        let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
        let params = Params {
            address: Some(input_addr.to_string()),
            hl: None,
        };

        let query = params.build_query();
        let resolved = uc
            .resolve_did_uri(format!("did:prople:test?{}", query.unwrap()))
            .await;
        assert!(resolved.is_err());
        assert!(resolved
            .unwrap_err()
            .to_string()
            .contains(&"missing hashlink".to_string()))
    }

    #[tokio::test]
    async fn test_resolve_did_uri_failed_invalid_addr() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();

        let uc = generate_usecase(repo, rpc);

        let params = Params {
            address: Some("invalid-addr".to_string()),
            hl: Some("test-hl".to_string()),
        };

        let query = params.build_query();
        let resolved = uc
            .resolve_did_uri(format!("did:prople:test?{}", query.unwrap()))
            .await;
        assert!(resolved.is_err());
        assert!(resolved
            .unwrap_err()
            .to_string()
            .contains(&"invalid multiaddr".to_string()))
    }

    #[tokio::test]
    async fn test_resolve_did_uri_failed_invalid_hl() {
        let did = DID::new();
        let did_cloned = did.clone();

        let identity = did.identity().unwrap();

        let identity_repo_clone = identity.clone();
        let identity_repo_clone_doc = identity.clone().to_doc();
        let identity_repo_clone_doc_private_keys = identity
            .clone()
            .build_private_keys("password".to_string())
            .unwrap();

        let identity_clone = identity.clone();
        let identity_clone_doc = identity.clone().to_doc();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().returning(move || {
            let did = did_cloned.clone();
            let identity_repo_clone = identity_repo_clone.clone();
            let identity_repo_clone_doc = identity_repo_clone_doc.clone();
            let identity_repo_clone_doc_private_keys = identity_repo_clone_doc_private_keys.clone();

            let mut expected = MockFakeRepo::new();
            expected.expect_save_account().returning(|_| Ok(()));
            expected.expect_get_account_by_did().returning(move |_| {
                let keysecure = did
                    .account()
                    .privkey()
                    .to_keysecure(Password::from("password".to_string()))
                    .unwrap();

                let account = Account::new(
                    identity_repo_clone.clone().value(),
                    identity_repo_clone_doc.clone(),
                    identity_repo_clone_doc_private_keys.clone(),
                    keysecure,
                );
                Ok(account)
            });

            expected
        });

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRPCClient::new();
            expected
                .expect_resolve_did_doc()
                .times(1)
                .withf(move |addr: &Multiaddr, did: &String| {
                    let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
                    addr == &input_addr && did == &identity_clone.value()
                })
                .returning(move |_, _| Ok(identity_clone_doc.clone()));

            expected
        });

        let uc = generate_usecase(repo, rpc);
        let account = uc.generate_did("password".to_string()).await;
        assert!(!account.is_err());

        let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
        let params = Params {
            address: Some(input_addr.to_string()),
            hl: Some("invalid-hl".to_string()),
        };

        let uri = URI::build_with_raw(did, Some(params));
        let resolved = uc.resolve_did_uri(uri.unwrap()).await;
        assert!(resolved.is_err());
        assert!(resolved
            .unwrap_err()
            .to_string()
            .contains(&"error hashlink".to_string()))
    }

    #[tokio::test]
    async fn test_resolve_did_doc_success() {
        let did = DID::new();
        let identity = did.identity().unwrap();

        let identity_repo_clone = identity.clone();
        let identity_repo_clone_doc = identity.clone().to_doc();
        let identity_repo_clone_doc_private_keys = identity
            .clone()
            .build_private_keys("password".to_string())
            .unwrap();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected
                .expect_get_account_by_did()
                .times(1)
                .withf(|did: &String| did.eq(&"did:prople:test".to_string()))
                .returning(move |_| {
                    let keysecure = did
                        .account()
                        .privkey()
                        .to_keysecure(Password::from("password".to_string()))
                        .unwrap();

                    let account = Account::new(
                        identity_repo_clone.clone().value(),
                        identity_repo_clone_doc.clone(),
                        identity_repo_clone_doc_private_keys.clone(),
                        keysecure,
                    );
                    Ok(account)
                });

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc);
        let doc = uc.resolve_did_doc("did:prople:test".to_string()).await;
        assert!(!doc.is_err());
        assert_eq!(
            identity.clone().to_doc().to_json().unwrap().to_bytes(),
            doc.unwrap().to_json().unwrap().to_bytes()
        )
    }

    #[tokio::test]
    async fn test_resolve_did_doc_missing_did() {
        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected
                .expect_get_account_by_did()
                .times(1)
                .withf(|did: &String| did.eq(&"did:prople:test".to_string()))
                .returning(move |_| Err(AccountError::DIDNotFound));

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc);
        let doc = uc.resolve_did_doc("did:prople:test".to_string()).await;
        assert!(doc.is_err());
        assert!(matches!(doc.unwrap_err(), AccountError::DIDNotFound))
    }
}
