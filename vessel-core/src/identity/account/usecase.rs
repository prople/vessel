use prople_crypto::keysecure::types::ToKeySecure;

use prople_did_core::did::{query::Params, DID};
use prople_did_core::doc::types::{Doc, ToDoc};
use prople_did_core::hashlink::verify_from_json;

use crate::ssi::account::types::{
    Account, AccountError, AccountRPCClientBuilder, AccountRepositoryBuilder, AccountUsecaseBuilder,
};

/// `Usecase` is base logic implementation for the [`AccountUsecaseBuilder`]
///
/// This object depends on the implementation of [`AccountRepositoryBuilder`]
pub struct Usecase<TRepo, TRPCClient>
where
    TRepo: AccountRepositoryBuilder,
    TRPCClient: AccountRPCClientBuilder,
{
    repo: TRepo,
    rpc: TRPCClient,
}

impl<TRepo, TRPCClient> Usecase<TRepo, TRPCClient>
where
    TRepo: AccountRepositoryBuilder,
    TRPCClient: AccountRPCClientBuilder,
{
    pub fn new(repo: TRepo, rpc: TRPCClient) -> Self {
        Self { repo, rpc }
    }
}

impl<TRepo, TRPCClient> AccountUsecaseBuilder for Usecase<TRepo, TRPCClient>
where
    TRepo: AccountRepositoryBuilder,
    TRPCClient: AccountRPCClientBuilder,
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

        let doc = identity.to_doc();
        let account = Account::new(identity.value(), doc, account_keysecure);

        let _ = self
            .repo
            .save(&account)
            .map_err(|err| AccountError::GenerateIdentityError(err.to_string()))?;

        Ok(account)
    }

    fn build_did_uri(
        &self,
        did: String,
        password: String,
        params: Option<Params>,
    ) -> Result<String, AccountError> {
        let account = self
            .repo
            .get_by_did(did)
            .map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        let did = DID::from_keysecure(password, account.keysecure)
            .map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        did.build_uri(params)
            .map_err(|err| AccountError::BuildURIError(err.to_string()))
    }

    fn resolve_did_uri(&self, uri: String) -> Result<Doc, AccountError> {
        let parsed =
            DID::parse_uri(uri).map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        if parsed.1.hl.is_none() {
            return Err(AccountError::ResolveDIDError(
                "invalid hashlink value".to_string(),
            ));
        }

        let parsed_addr = parsed
            .1
            .parse_multiaddr()
            .map_err(|err| AccountError::ResolveDIDError(err.to_string()))?
            .ok_or(AccountError::ResolveDIDError(
                "unable to parse MultiAddress format".to_string(),
            ))?;

        let doc = self.rpc.resolve_did_doc(parsed_addr, parsed.0)?;
        verify_from_json(doc.clone(), parsed.1.hl.unwrap())
            .map_err(|err| AccountError::ResolveDIDError(err.to_string()))?;

        Ok(doc)
    }

    fn resolve_did_doc(&self, did: String) -> Result<Doc, AccountError> {
        let account = self.repo.get_by_did(did)?;
        Ok(account.doc)
    }

    fn remove_did(&self, did: String) -> Result<(), AccountError> {
        self.repo.remove_by_did(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use multiaddr::{multiaddr, Multiaddr};

    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::hashlink::generate_from_json;
    use prople_did_core::types::ToJSON;

    mock!(
        FakeRepo{}

        impl AccountRepositoryBuilder for FakeRepo {
            fn save(&self, account: &Account) -> Result<(), AccountError>;
            fn remove_by_did(&self, did: String) -> Result<(), AccountError>;
            fn get_by_did(&self, did: String) -> Result<Account, AccountError>;
        }
    );

    mock!(
        FakeRPCClient{}

        impl AccountRPCClientBuilder for FakeRPCClient {
            fn resolve_did_doc(&self, addr: Multiaddr, did: String) -> Result<Doc, AccountError>;
        }
    );

    fn generate_usecase<TRepo: AccountRepositoryBuilder, TRPCClient: AccountRPCClientBuilder>(
        repo: TRepo,
        rpc: TRPCClient,
    ) -> Usecase<TRepo, TRPCClient> {
        Usecase::new(repo, rpc)
    }

    #[test]
    fn test_storage_repo_success() {
        let mut repo = MockFakeRepo::new();
        repo.expect_save().returning(|_| Ok(()));

        let rpc = MockFakeRPCClient::new();

        let uc = generate_usecase(repo, rpc);
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

        let rpc = MockFakeRPCClient::new();

        let uc = generate_usecase(repo, rpc);
        let output = uc.generate_did("password".to_string());
        assert!(output.is_err());
        assert!(matches!(
            output.unwrap_err(),
            AccountError::GenerateIdentityError(_)
        ))
    }

    #[test]
    fn test_build_did_uri_without_params() {
        let did = DID::new();
        let identity = did.identity().unwrap();

        let identity_value = identity.value();
        let identity_doc = identity.to_doc();

        let mut repo = MockFakeRepo::new();
        repo.expect_save().returning(|_| Ok(()));
        repo.expect_get_by_did().returning(move |_| {
            let keysecure = did
                .account()
                .privkey()
                .to_keysecure("password".to_string())
                .unwrap();
            let account = Account::new(identity_value.clone(), identity_doc.clone(), keysecure);
            Ok(account)
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc);
        let uri = uc.build_did_uri(identity.clone().value(), "password".to_string(), None);
        assert!(!uri.is_err());
        assert_eq!(uri.unwrap(), identity.clone().value())
    }

    #[test]
    fn test_build_did_uri_with_params() {
        let did = DID::new();
        let identity = did.identity().unwrap();

        let identity_value = identity.value();
        let identity_doc = identity.to_doc();

        let mut repo = MockFakeRepo::new();
        repo.expect_save().returning(|_| Ok(()));
        repo.expect_get_by_did().returning(move |_| {
            let keysecure = did
                .account()
                .privkey()
                .to_keysecure("password".to_string())
                .unwrap();
            let account = Account::new(identity_value.clone(), identity_doc.clone(), keysecure);
            Ok(account)
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
            service: Some("peer".to_string()),
        };

        let uri = uc.build_did_uri(
            identity.clone().value(),
            "password".to_string(),
            Some(params),
        );
        assert!(!uri.is_err());

        let uri_expected = format!(
            "{}?service=peer&address=test-addr&hl={}",
            identity.clone().value(),
            doc_hl
        );
        assert_eq!(uri.unwrap(), uri_expected)
    }

    #[test]
    fn test_resolve_did_uri_success() {
        let did = DID::new();
        let identity = did.identity().unwrap();

        let identity_repo_clone = identity.clone();
        let identity_repo_clone_doc = identity.clone().to_doc();

        let identity_clone = identity.clone();
        let identity_clone_doc = identity.clone().to_doc();

        let mut repo = MockFakeRepo::new();
        repo.expect_save().times(1).returning(|_| Ok(()));
        repo.expect_get_by_did().times(1).returning(move |_| {
            let keysecure = did
                .account()
                .privkey()
                .to_keysecure("password".to_string())
                .unwrap();
            let account = Account::new(
                identity_repo_clone.clone().value(),
                identity_repo_clone_doc.clone(),
                keysecure,
            );
            Ok(account)
        });

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_resolve_did_doc()
            .times(1)
            .withf(move |addr: &Multiaddr, did: &String| {
                let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
                addr == &input_addr && did == &identity_clone.value()
            })
            .returning(move |_, _| Ok(identity_clone_doc.clone()));

        let uc = generate_usecase(repo, rpc);
        let account = uc.generate_did("password".to_string());
        assert!(!account.is_err());

        let doc_hl_result = generate_from_json(identity.clone().to_doc());
        assert!(!doc_hl_result.is_err());

        let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
        let params = Params {
            address: Some(input_addr.to_string()),
            hl: Some(doc_hl_result.unwrap()),
            service: Some("peer".to_string()),
        };

        let uri = uc.build_did_uri(
            identity.clone().value(),
            "password".to_string(),
            Some(params),
        );
        assert!(!uri.is_err());

        let resolved = uc.resolve_did_uri(uri.unwrap());
        assert!(!resolved.is_err());
        assert_eq!(
            resolved.unwrap().to_json().unwrap().as_bytes(),
            identity.to_doc().to_json().unwrap().as_bytes()
        )
    }

    #[test]
    fn test_resolve_did_uri_failed_missing_hl() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();

        let uc = generate_usecase(repo, rpc);

        let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
        let params = Params {
            address: Some(input_addr.to_string()),
            hl: None,
            service: Some("peer".to_string()),
        };

        let query = params.build_query();
        let resolved = uc.resolve_did_uri(format!("did:prople:test?{}", query.unwrap()));
        assert!(resolved.is_err());
        assert!(resolved
            .unwrap_err()
            .to_string()
            .contains(&"invalid hashlink value".to_string()))
    }

    #[test]
    fn test_resolve_did_uri_failed_invalid_addr() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();

        let uc = generate_usecase(repo, rpc);

        let params = Params {
            address: Some("invalid-addr".to_string()),
            hl: Some("test-hl".to_string()),
            service: Some("peer".to_string()),
        };

        let query = params.build_query();
        let resolved = uc.resolve_did_uri(format!("did:prople:test?{}", query.unwrap()));
        assert!(resolved.is_err());
        assert!(resolved
            .unwrap_err()
            .to_string()
            .contains(&"invalid multiaddr".to_string()))
    }

    #[test]
    fn test_resolve_did_uri_failed_invalid_hl() {
        let did = DID::new();
        let identity = did.identity().unwrap();

        let identity_repo_clone = identity.clone();
        let identity_repo_clone_doc = identity.clone().to_doc();

        let identity_clone = identity.clone();
        let identity_clone_doc = identity.clone().to_doc();

        let mut repo = MockFakeRepo::new();
        repo.expect_save().times(1).returning(|_| Ok(()));
        repo.expect_get_by_did().times(1).returning(move |_| {
            let keysecure = did
                .account()
                .privkey()
                .to_keysecure("password".to_string())
                .unwrap();
            let account = Account::new(
                identity_repo_clone.clone().value(),
                identity_repo_clone_doc.clone(),
                keysecure,
            );
            Ok(account)
        });

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_resolve_did_doc()
            .times(1)
            .withf(move |addr: &Multiaddr, did: &String| {
                let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
                addr == &input_addr && did == &identity_clone.value()
            })
            .returning(move |_, _| Ok(identity_clone_doc.clone()));

        let uc = generate_usecase(repo, rpc);
        let account = uc.generate_did("password".to_string());
        assert!(!account.is_err());

        let input_addr = multiaddr!(Ip4([127, 0, 0, 1]), Tcp(8080u16));
        let params = Params {
            address: Some(input_addr.to_string()),
            hl: Some("invalid-hl".to_string()),
            service: Some("peer".to_string()),
        };

        let uri = uc.build_did_uri(
            identity.clone().value(),
            "password".to_string(),
            Some(params),
        );
        assert!(!uri.is_err());

        let resolved = uc.resolve_did_uri(uri.unwrap());
        assert!(resolved.is_err());
        assert!(resolved
            .unwrap_err()
            .to_string()
            .contains(&"error hashlink".to_string()))
    }

    #[test]
    fn test_resolve_did_doc_success() {
        let did = DID::new();
        let identity = did.identity().unwrap();

        let identity_repo_clone = identity.clone();
        let identity_repo_clone_doc = identity.clone().to_doc();

        let mut repo = MockFakeRepo::new();
        repo.expect_get_by_did()
            .times(1)
            .withf(|did: &String| did.eq(&"did:prople:test".to_string()))
            .returning(move |_| {
                let keysecure = did
                    .account()
                    .privkey()
                    .to_keysecure("password".to_string())
                    .unwrap();

                let account = Account::new(
                    identity_repo_clone.clone().value(),
                    identity_repo_clone_doc.clone(),
                    keysecure,
                );
                Ok(account)
            });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc);
        let doc = uc.resolve_did_doc("did:prople:test".to_string());
        assert!(!doc.is_err());
        assert_eq!(
            identity.clone().to_doc().to_json().unwrap().as_bytes(),
            doc.unwrap().to_json().unwrap().as_bytes()
        )
    }

    #[test]
    fn test_resolve_did_doc_missing_did() {
        let mut repo = MockFakeRepo::new();
        repo.expect_get_by_did()
            .times(1)
            .withf(|did: &String| did.eq(&"did:prople:test".to_string()))
            .returning(move |_| Err(AccountError::DIDNotFound));

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc);
        let doc = uc.resolve_did_doc("did:prople:test".to_string());
        assert!(doc.is_err());
        assert!(matches!(doc.unwrap_err(), AccountError::DIDNotFound))
    }
}
