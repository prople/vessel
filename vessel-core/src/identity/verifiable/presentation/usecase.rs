use multiaddr::Multiaddr;

use rst_common::standard::async_trait::async_trait;

use crate::identity::account::types::AccountAPI;
use crate::identity::account::Account;

use crate::identity::verifiable::credential::types::CredentialAPI;
use crate::identity::verifiable::proof::types::Params as ProofParams;
use crate::identity::verifiable::types::VerifiableError;
use crate::identity::verifiable::Credential;

use super::types::{PresentationAPI, PresentationError, RepoBuilder, RpcBuilder, UsecaseBuilder};
use super::Presentation;

#[derive(Clone)]
pub struct Usecase<TRPCClient, TRepo, TAccountAPI, TCredentialAPI>
where
    TRPCClient: RpcBuilder,
    TRepo: RepoBuilder<EntityAccessor = Presentation>,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
    TCredentialAPI: CredentialAPI<EntityAccessor = Credential>,
{
    repo: TRepo,
    rpc: TRPCClient,
    account: TAccountAPI,
    credential: TCredentialAPI,
}

impl<TRPCClient, TRepo, TAccountAPI, TCredentialAPI>
    Usecase<TRPCClient, TRepo, TAccountAPI, TCredentialAPI>
where
    TRPCClient: RpcBuilder,
    TRepo: RepoBuilder<EntityAccessor = Presentation>,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
    TCredentialAPI: CredentialAPI<EntityAccessor = Credential>,
{
    pub fn new(
        repo: TRepo,
        rpc: TRPCClient,
        account: TAccountAPI,
        credential: TCredentialAPI,
    ) -> Self {
        Self {
            repo,
            rpc,
            account,
            credential,
        }
    }
}

impl<TRPCClient, TRepo, TAccountAPI, TCredentialAPI> UsecaseBuilder<Presentation, Account>
    for Usecase<TRPCClient, TRepo, TAccountAPI, TCredentialAPI>
where
    TRPCClient: RpcBuilder,
    TRepo: RepoBuilder<EntityAccessor = Presentation>,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
    TCredentialAPI: CredentialAPI<EntityAccessor = Credential> + Sync + Send,
{
    type AccountAPIImplementer = TAccountAPI;
    type CredentialAPIImplementer = TCredentialAPI;
    type RpcImplementer = TRPCClient;
    type RepoImplementer = TRepo;

    fn account(&self) -> Self::AccountAPIImplementer {
        self.account.to_owned()
    }

    fn credential(&self) -> Self::CredentialAPIImplementer {
        self.credential.to_owned()
    }

    fn repo(&self) -> Self::RepoImplementer {
        self.repo.to_owned()
    }

    fn rpc(&self) -> Self::RpcImplementer {
        self.rpc.to_owned()
    }
}

#[async_trait]
impl<TRPCClient, TRepo, TAccountAPI, TCredentialAPI> PresentationAPI
    for Usecase<TRPCClient, TRepo, TAccountAPI, TCredentialAPI>
where
    TRPCClient: RpcBuilder,
    TRepo: RepoBuilder<EntityAccessor = Presentation>,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
    TCredentialAPI: CredentialAPI<EntityAccessor = Credential> + Sync + Send,
{
    type EntityAccessor = Presentation;

    async fn get_by_id(&self, id: String) -> Result<Self::EntityAccessor, PresentationError> {
        self.repo().get_by_id(id).await
    }

    async fn send_to_verifier(
        &self,
        id: String,
        receiver: Multiaddr,
    ) -> Result<(), PresentationError> {
        if id.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("id was missing".to_string()),
            ));
        }

        let presentation = self.repo().get_by_id(id).await?;
        self.rpc().send_to_verifier(receiver, presentation.vp).await
    }

    async fn generate(
        &self,
        password: String,
        did_issuer: String,
        credentials: Vec<String>,
        proof_params: Option<ProofParams>,
    ) -> Result<Self::EntityAccessor, PresentationError> {
        if password.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("password was missing".to_string()),
            ));
        }

        if did_issuer.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("did_issuer was missing".to_string()),
            ));
        }

        let vcs = self
            .credential()
            .list_credentials_by_ids(credentials)
            .await
            .map_err(|err| PresentationError::GenerateError(err.to_string()))?;

        let account = self
            .account()
            .get_account_did(did_issuer.clone())
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::DIDError(err.to_string()))
            })?;

        let presentation =
            Presentation::generate(password, did_issuer, account, vcs, proof_params)?;

        let _ = self.repo().save(&presentation.clone()).await?;
        Ok(presentation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use mockall::predicate::eq;

    use multiaddr::{multiaddr, Multiaddr};

    use rst_common::standard::serde_json::value::Value;

    use prople_crypto::eddsa::keypair::KeyPair;
    use prople_crypto::keysecure::types::ToKeySecure;

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::keys::{IdentityPrivateKeyPairs, IdentityPrivateKeyPairsBuilder};
    use prople_did_core::verifiable::objects::ProofValue;
    use prople_did_core::verifiable::objects::VC;
    use prople_did_core::verifiable::objects::VP;

    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::with_tokio::tokio;

    use crate::identity::account::types::AccountError;
    use crate::identity::account::Account as AccountIdentity;
    use crate::identity::verifiable::credential::types::CredentialError;
    use crate::identity::verifiable::types::{PaginationParams, VerifiableError};

    use super::Presentation;

    mock!(
        FakeRepo{}

        impl Clone for FakeRepo {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RepoBuilder for FakeRepo {
            type EntityAccessor = Presentation;

            async fn save(&self, data: &Presentation) -> Result<(), PresentationError>;
            async fn get_by_id(&self, id: String) -> Result<Presentation, PresentationError>;
        }
    );

    mock!(
        FakeRPCClient{}

        impl Clone for FakeRPCClient {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RpcBuilder for FakeRPCClient {
            async fn send_to_verifier(&self, addr: Multiaddr, vp: VP) -> Result<(), PresentationError>;
        }
    );

    mock!(
        FakeAccountUsecase{}

        impl Clone for FakeAccountUsecase {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl AccountAPI for FakeAccountUsecase {
            type EntityAccessor = Account;

            async fn generate_did(&self, password: String) -> Result<AccountIdentity, AccountError>;
            async fn build_did_uri(
                &self,
                did: String,
                password: String,
                params: Option<Params>,
            ) -> Result<String, AccountError>;
            async fn resolve_did_uri(&self, uri: String) -> Result<Doc, AccountError>;
            async fn resolve_did_doc(&self, did: String) -> Result<Doc, AccountError>;
            async fn remove_did(&self, did: String) -> Result<(), AccountError>;
            async fn get_account_did(&self, did: String) -> Result<AccountIdentity, AccountError>;
        }
    );

    mock!(
        FakeCredentialUsecase{}

        impl Clone for FakeCredentialUsecase {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl CredentialAPI for FakeCredentialUsecase {
            type EntityAccessor = Credential;

            async fn generate_credential(
                &self,
                password: String,
                did_issuer: String,
                credential: Value,
                proof_params: Option<ProofParams>,
            ) -> Result<Credential, CredentialError>;

            async fn send_credential_to_holder(
                &self,
                id: String,
                receiver: Multiaddr,
            ) -> Result<(), CredentialError>;

            async fn receive_credential_by_holder(
                &self,
                request_id: String,
                issuer_addr: String,
                vc: VC,
            ) -> Result<(), CredentialError>;

            async fn list_credentials_by_did(
                &self,
                did: String,
                pagination: Option<PaginationParams>,
            ) -> Result<Vec<Credential>, CredentialError>;

            async fn list_credentials_by_ids(
                &self,
                ids: Vec<String>,
            ) -> Result<Vec<Credential>, CredentialError>;
        }
    );

    #[derive(Deserialize, Serialize)]
    #[serde(crate = "self::serde")]
    struct FakeCredential {
        pub msg: String,
    }

    fn generate_did() -> DID {
        DID::new()
    }

    fn generate_usecase<
        TRepo: RepoBuilder<EntityAccessor = Presentation>,
        TRPCClient: RpcBuilder,
        TAccount: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
        TCredentialAPI: CredentialAPI<EntityAccessor = Credential>,
    >(
        repo: TRepo,
        rpc: TRPCClient,
        account: TAccount,
        credential: TCredentialAPI,
    ) -> Usecase<TRPCClient, TRepo, TAccount, TCredentialAPI> {
        Usecase::new(repo, rpc, account, credential)
    }

    fn generate_credentials() -> Vec<Credential> {
        let mut creds = Vec::<Credential>::new();

        let did1 = generate_did();
        let did1_keysecure = did1
            .account()
            .privkey()
            .to_keysecure("password".to_string())
            .unwrap();

        let did2 = generate_did();
        let did2_keysecure = did2
            .account()
            .privkey()
            .to_keysecure("password".to_string())
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

    #[tokio::test]
    async fn test_generate_without_params() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();
        let did_issuer_mock = did_issuer.clone();

        let creds = generate_credentials();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save().returning(|_| Ok(()));

            expected
        });

        let mut account = MockFakeAccountUsecase::new();
        account.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeAccountUsecase::new();
            expected.expect_get_account_did().returning(move |_| {
                let did_issuer_mock_doc = did_issuer_mock
                    .identity()
                    .unwrap()
                    .build_assertion_method()
                    .build_auth_method()
                    .to_doc();

                let did_issuer_doc_private_keys = did_issuer_mock
                    .identity()
                    .unwrap()
                    .build_private_keys("password".to_string())
                    .unwrap();

                let did_issuer_mock_keysecure = did_issuer_mock
                    .account()
                    .privkey()
                    .to_keysecure("password".to_string())
                    .unwrap();

                let result = AccountIdentity::new(
                    did_issuer_mock.identity().unwrap().value(),
                    did_issuer_mock_doc,
                    did_issuer_doc_private_keys,
                    did_issuer_mock_keysecure,
                );

                Ok(result)
            });

            expected
        });

        let mut credential = MockFakeCredentialUsecase::new();
        credential.expect_clone().times(1).return_once(move || {
            let creds = creds.clone();
            let mut expected = MockFakeCredentialUsecase::new();
            expected
                .expect_list_credentials_by_ids()
                .returning(move |_| Ok(creds.clone()));

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc, account, credential);
        let result = uc
            .generate(
                "password".to_string(),
                did_issuer_value,
                vec!["id1".to_string(), "id2".to_string()],
                None,
            )
            .await;

        assert!(!result.is_err());

        let did_issuer_identity = did_issuer.identity().unwrap();
        let presentation = result.unwrap();
        assert!(presentation.vp.holder.is_some());
        assert!(presentation.vp.verifiable_credential.len() == 2);
        assert_eq!(presentation.vp.holder.unwrap(), did_issuer_identity.value());
    }

    #[tokio::test]
    async fn test_generate_with_params() {
        let did_issuer = generate_did();

        let mut did_issuer_identity = did_issuer.identity().unwrap();
        did_issuer_identity
            .build_assertion_method()
            .build_auth_method();

        let did_issuer_value = did_issuer_identity.value();
        let did_issuer_mock = did_issuer.clone();

        let creds = generate_credentials();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save().returning(|_| Ok(()));

            expected
        });

        let mut credential = MockFakeCredentialUsecase::new();
        credential.expect_clone().times(1).return_once(move || {
            let creds = creds.clone();
            let mut expected = MockFakeCredentialUsecase::new();
            expected
                .expect_list_credentials_by_ids()
                .returning(move |_| Ok(creds.clone()));

            expected
        });

        let mut account = MockFakeAccountUsecase::new();
        account.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeAccountUsecase::new();

            expected.expect_get_account_did().returning(move |_| {
                let mut did_issuer_mock_identity = did_issuer_mock.identity().unwrap();
                let did_issuer_mock_doc = did_issuer_mock_identity
                    .build_assertion_method()
                    .build_auth_method()
                    .to_doc();

                let did_issuer_mock_doc_private_keys = did_issuer_mock_identity
                    .build_private_keys("password".to_string())
                    .unwrap();

                let did_issuer_mock_keysecure = did_issuer_mock
                    .account()
                    .privkey()
                    .to_keysecure("password".to_string())
                    .unwrap();

                let result = AccountIdentity::new(
                    did_issuer_mock.identity().unwrap().value(),
                    did_issuer_mock_doc,
                    did_issuer_mock_doc_private_keys,
                    did_issuer_mock_keysecure,
                );

                Ok(result)
            });

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc, account, credential);

        let proof_params = ProofParams {
            id: "uid".to_string(),
            typ: "type".to_string(),
            method: "method".to_string(),
            purpose: "purpose".to_string(),
            cryptosuite: None,
            expires: None,
            nonce: None,
        };

        let result = uc
            .generate(
                "password".to_string(),
                did_issuer_value,
                vec!["id1".to_string(), "id2".to_string()],
                Some(proof_params),
            )
            .await;

        assert!(!result.is_err());

        // verify proof
        let presentation = result.unwrap();
        let vp = presentation.vp;

        let privkeys = presentation.private_keys;
        let account_doc_verification_pem_bytes = privkeys
            .clone()
            .authentication
            .map(|val| {
                val.decrypt_verification("password".to_string())
                    .map_err(|err| PresentationError::GenerateError(err.to_string()))
            })
            .ok_or(PresentationError::GenerateError(
                "PrivateKeyPairs is missing".to_string(),
            ));
        assert!(!account_doc_verification_pem_bytes.is_err());

        let account_doc_verification_pem_bytes_unwrap =
            account_doc_verification_pem_bytes.unwrap().unwrap();

        let account_doc_verification_pem =
            String::from_utf8(account_doc_verification_pem_bytes_unwrap)
                .map_err(|err| PresentationError::GenerateError(err.to_string()));
        assert!(!account_doc_verification_pem.is_err());

        let account_doc_keypair = KeyPair::from_pem(account_doc_verification_pem.unwrap())
            .map_err(|err| PresentationError::GenerateError(err.to_string()));
        assert!(!account_doc_keypair.is_err());

        let (vp_original, proof) = vp.split_proof();
        assert!(proof.is_some());

        let verified = ProofValue::transform_verifier(
            account_doc_keypair.clone().unwrap(),
            vp_original,
            proof.clone().unwrap().proof_value,
        );

        assert!(!verified.is_err());
        assert!(verified.unwrap());

        // verification should be error if using VP directly
        let verified_invalid = ProofValue::transform_verifier(
            account_doc_keypair.unwrap(),
            vp,
            proof.unwrap().proof_value,
        );

        assert!(!verified_invalid.is_err());
        assert!(!verified_invalid.unwrap());
    }

    #[tokio::test]
    async fn test_send_to_verifier() {
        let presentation = generate_presentation();
        let presentation_mock = presentation.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected
                .expect_get_by_id()
                .with(eq("id1".to_string()))
                .returning(move |_| Ok(presentation_mock.clone()));

            expected
        });

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let addr_cloned = addr.clone();

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRPCClient::new();
            expected
                .expect_send_to_verifier()
                .with(eq(addr_cloned), eq(presentation.vp))
                .times(1)
                .returning(|_, _| Ok(()));

            expected
        });

        let account = MockFakeAccountUsecase::new();
        let credential = MockFakeCredentialUsecase::new();

        let uc = generate_usecase(repo, rpc, account, credential);
        let send_output = uc.send_to_verifier("id1".to_string(), addr).await;
        assert!(!send_output.is_err())
    }

    #[tokio::test]
    async fn test_send_to_verifier_validation_error() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();
        let credential = MockFakeCredentialUsecase::new();

        let uc = generate_usecase(repo, rpc, account, credential);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let send_output = uc.send_to_verifier("".to_string(), addr).await;
        assert!(send_output.is_err());

        let send_output_err = send_output.unwrap_err();
        assert!(matches!(send_output_err, PresentationError::CommonError(_)));

        if let PresentationError::CommonError(msg) = send_output_err {
            assert!(msg.to_string().contains("id"))
        }
    }

    #[tokio::test]
    async fn test_send_to_verifier_repo_error() {
        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected
                .expect_get_by_id()
                .with(eq("id1".to_string()))
                .returning(move |_| {
                    Err(PresentationError::CommonError(VerifiableError::RepoError(
                        "error repo".to_string(),
                    )))
                });

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();
        let credential = MockFakeCredentialUsecase::new();

        let uc = generate_usecase(repo, rpc, account, credential);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let send_output = uc.send_to_verifier("id1".to_string(), addr).await;
        assert!(send_output.is_err());

        let send_output_err = send_output.unwrap_err();
        assert!(matches!(send_output_err, PresentationError::CommonError(_)));
    }
}
