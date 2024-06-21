use multiaddr::Multiaddr;

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::serde_json::Value;

use prople_did_core::verifiable::objects::VC;

use crate::identity::account::types::AccountAPI;
use crate::identity::account::Account;

use crate::identity::verifiable::proof::types::Params as ProofParams;
use crate::identity::verifiable::types::{PaginationParams, VerifiableError};

use super::types::{CredentialAPI, RPCBuilder, RepoBuilder, UsecaseBuilder};
use super::{Credential, Holder};

pub struct Usecase<TRPCClient, TRepo, TAccountAPI>
where
    TRPCClient: RPCBuilder + Clone + Sync + Send,
    TRepo: RepoBuilder<CredentialEntityAccessor = Credential, HolderEntityAccessor = Holder> + Clone + Sync + Send,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
{
    repo: TRepo,
    rpc: TRPCClient,
    account: TAccountAPI,
}

impl<TRPCClient, TRepo, TAccountAPI> Usecase<TRPCClient, TRepo, TAccountAPI>
where
    TRPCClient: RPCBuilder + Clone + Sync + Send,
    TRepo: RepoBuilder<CredentialEntityAccessor = Credential, HolderEntityAccessor = Holder> + Clone + Sync + Send,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
{
    pub fn new(repo: TRepo, rpc: TRPCClient, account: TAccountAPI) -> Self {
        Self { repo, rpc, account }
    }
}

impl<TRPCClient, TRepo, TAccountAPI> UsecaseBuilder<Account, Credential, Holder> for Usecase<TRPCClient, TRepo, TAccountAPI>
where
    TRPCClient: RPCBuilder + Clone + Sync + Send,
    TRepo: RepoBuilder<CredentialEntityAccessor = Credential, HolderEntityAccessor = Holder> + Clone + Sync + Send,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
{
    type AccountAPIImplementer = TAccountAPI;
    type RPCImplementer = TRPCClient;
    type RepoImplementer = TRepo;
    
    fn account(&self) -> Self::AccountAPIImplementer {
        self.account.clone()
    }

    fn repo(&self) -> Self::RepoImplementer {
        self.repo.clone()
    }

    fn rpc(&self) -> Self::RPCImplementer {
        self.rpc.clone()
    }
}


#[async_trait]
impl<TRPCClient, TRepo, TAccountAPI> CredentialAPI for Usecase<TRPCClient, TRepo, TAccountAPI> 
where
    TRPCClient: RPCBuilder + Clone + Sync + Send,
    TRepo: RepoBuilder<CredentialEntityAccessor = Credential, HolderEntityAccessor = Holder> + Clone + Sync + Send,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
{
    type EntityAccessor = Credential;

    async fn generate_credential(
        &self,
        password: String,
        did_issuer: String,
        claims: Value,
        proof_params: Option<ProofParams>,
    ) -> Result<Credential, VerifiableError> {
        if password.is_empty() {
            return Err(VerifiableError::ValidationError(
                "password was missing".to_string(),
            ));
        }

        if did_issuer.is_empty() {
            return Err(VerifiableError::ValidationError(
                "did_issuer was missing".to_string(),
            ));
        }

        let credential =
            Credential::generate(self.account(), password, did_issuer, claims, proof_params)
                .await?;

        let _ = self
            .repo()
            .save_credential(&credential.clone())
            .await
            .map_err(|err| VerifiableError::RepoError(err.to_string()))?;

        Ok(credential)
    }

    async fn list_credentials(
        &self,
        did: String,
        pagination: Option<PaginationParams>,
    ) -> Result<Vec<Credential>, VerifiableError> {
        self.repo().list_credentials_by_did(did, pagination).await
    }

    async fn receive_credential_by_holder(
        &self,
        request_id: String,
        issuer_addr: String,
        vc: VC,
    ) -> Result<(), VerifiableError> {
        if request_id.is_empty() {
            return Err(VerifiableError::ValidationError(
                "request_id was missing".to_string(),
            ));
        }

        if issuer_addr.is_empty() {
            return Err(VerifiableError::ValidationError(
                "issuer_addr was missing".to_string(),
            ));
        }

        let cred_holder = Holder::new(request_id, issuer_addr, vc)?;
        self.repo().save_credential_holder(&cred_holder).await
    }

    async fn send_credential_to_holder(
        &self,
        id: String,
        receiver: Multiaddr,
    ) -> Result<(), VerifiableError> {
        if id.is_empty() {
            return Err(VerifiableError::ValidationError(
                "id was missing".to_string(),
            ));
        }

        let cred = self.repo().get_credential_by_id(id).await?;
        self.rpc().send_credential_to_holder(receiver, cred.vc).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use mockall::predicate::eq;

    use rst_common::standard::async_trait::async_trait;
    use rst_common::standard::chrono::Utc;
    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::standard::serde_json;
    use rst_common::standard::uuid::Uuid;
    use rst_common::with_tokio::tokio;

    use multiaddr::{multiaddr, Multiaddr};

    use prople_crypto::eddsa::keypair::KeyPair;
    use prople_crypto::keysecure::types::ToKeySecure;

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;
    use prople_did_core::verifiable::objects::{ProofValue, VC};

    use crate::identity::account::types::AccountError;
    use crate::identity::account::Account as AccountIdentity;

    mock!(
        FakeRepo{}

        impl Clone for FakeRepo {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RepoBuilder for FakeRepo {
            type CredentialEntityAccessor = Credential;
            type HolderEntityAccessor = Holder;

            async fn save_credential(&self, data: &Credential) -> Result<(), VerifiableError>;
            async fn save_credential_holder(&self, data: &Holder) -> Result<(), VerifiableError>;
            async fn remove_credential_by_id(&self, id: String) -> Result<(), VerifiableError>;
            async fn remove_credential_by_did(&self, did: String) -> Result<(), VerifiableError>;

            async fn get_credential_by_id(&self, id: String) -> Result<Credential, VerifiableError>;

            async fn list_credentials_by_ids(
                &self,
                ids: Vec<String>,
            ) -> Result<Vec<Credential>, VerifiableError>;

            async fn list_credentials_by_did(
                &self,
                did: String,
                pagination: Option<PaginationParams>,
            ) -> Result<Vec<Credential>, VerifiableError>;
        }
    );

    mock!(
        FakeRPCClient{}

        impl Clone for FakeRPCClient {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RPCBuilder for FakeRPCClient {
            async fn send_credential_to_holder(
                &self,
                addr: Multiaddr,
                vc: VC,
            ) -> Result<(), VerifiableError>;

            async fn verify_credential_to_issuer(
                &self,
                addr: Multiaddr,
                vc: VC,
            ) -> Result<(), VerifiableError>;
        }
    );

    mock!(
        FakeAccountUsecase{}

        impl Clone for FakeAccountUsecase {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl AccountAPI for FakeAccountUsecase {
            type EntityAccessor = AccountIdentity;

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

    #[derive(Deserialize, Serialize)]
    #[serde(crate = "self::serde")]
    struct FakeCredential {
        pub msg: String,
    }

    fn generate_usecase<
        TRepo: RepoBuilder<CredentialEntityAccessor = Credential, HolderEntityAccessor = Holder> + Clone + Sync + Send,
        TRPCClient: RPCBuilder + Clone + Sync + Send,
        TAccount: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
    >(
        repo: TRepo,
        rpc: TRPCClient,
        account: TAccount,
    ) -> Usecase<TRPCClient, TRepo, TAccount> {
        Usecase::new(repo, rpc, account)
    }

    fn generate_did() -> DID {
        DID::new()
    }

    #[tokio::test]
    async fn test_generate_success_without_params() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save_credential().returning(|_| Ok(()));

            expected
        });

        let mut account = MockFakeAccountUsecase::new();
        account.expect_clone().times(1).return_once(move || {
            let did_vc = did_vc_cloned;

            let mut expected = MockFakeAccountUsecase::new();
            expected
                .expect_generate_did()
                .with(eq("password".to_string()))
                .return_once(move |_| {
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

                    Ok(AccountIdentity {
                        id: Uuid::new_v4().to_string(),
                        did: did_vc_value_cloned.clone(),
                        keysecure: did_vc_keysecure,
                        doc: did_vc_doc,
                        doc_private_keys: did_vc_doc_private_keys,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    })
                });

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc, account);

        let cred_value = serde_json::to_value(FakeCredential {
            msg: "hello world".to_string(),
        })
        .unwrap();

        let vc = uc
            .generate_credential(
                "password".to_string(),
                did_issuer_value.clone(),
                cred_value.clone(),
                None,
            )
            .await;
        assert!(!vc.is_err());

        let credential = vc.unwrap();
        assert!(credential.vc.proof.is_none());
        assert_eq!(credential.did, did_issuer_value);
        assert_eq!(credential.vc.issuer, did_issuer_value);
        assert_eq!(credential.vc.id, did_vc.identity().unwrap().value());

        let vc_types = credential.vc.types;
        assert_eq!(vc_types.len(), 1);
        assert_eq!(vc_types[0], "VerifiableCredential".to_string());

        let vc_cred = credential.vc.credential_subject;
        assert_eq!(vc_cred, cred_value)
    }

    #[tokio::test]
    async fn test_generate_success_with_params() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save_credential().returning(|_| Ok(()));

            expected
        });

        let mut account = MockFakeAccountUsecase::new();
        account.expect_clone().times(1).return_once(move || {
            let did_vc = did_vc_cloned;

            let mut expected = MockFakeAccountUsecase::new();
            expected
                .expect_generate_did()
                .with(eq("password".to_string()))
                .return_once(move |_| {
                    let mut did_vc_identity = did_vc.identity().unwrap();
                    let did_vc_value_cloned = did_vc_identity.value();

                    let did_vc_doc = did_vc_identity
                        .build_auth_method()
                        .build_assertion_method()
                        .to_doc();

                    let did_vc_doc_private_keys = did_vc_identity
                        .build_private_keys("password".to_string())
                        .unwrap();

                    let did_vc_keysecure = did_vc
                        .account()
                        .privkey()
                        .to_keysecure("password".to_string())
                        .unwrap();

                    Ok(AccountIdentity {
                        id: Uuid::new_v4().to_string(),
                        did: did_vc_value_cloned.clone(),
                        keysecure: did_vc_keysecure,
                        doc: did_vc_doc,
                        doc_private_keys: did_vc_doc_private_keys,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    })
                });

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc, account);

        let cred_value = serde_json::to_value(FakeCredential {
            msg: "hello world".to_string(),
        })
        .unwrap();

        let proof_params = ProofParams {
            id: "uid".to_string(),
            typ: "type".to_string(),
            method: "method".to_string(),
            purpose: "purpose".to_string(),
            cryptosuite: None,
            expires: None,
            nonce: None,
        };

        let vc = uc
            .generate_credential(
                "password".to_string(),
                did_issuer_value.clone(),
                cred_value.clone(),
                Some(proof_params),
            )
            .await;
        assert!(!vc.is_err());

        let credential = vc.unwrap();
        assert!(credential.vc.proof.is_some());
        assert_eq!(credential.did, did_issuer_value);
        assert_eq!(credential.vc.issuer, did_issuer_value);
        assert_eq!(credential.vc.id, did_vc.identity().unwrap().value());

        let vc = credential.vc;
        let vc_types = vc.clone().types;
        assert_eq!(vc_types.len(), 1);
        assert_eq!(vc_types[0], "VerifiableCredential".to_string());

        let vc_cred = vc.clone().credential_subject;
        assert_eq!(vc_cred, cred_value);

        // verify generated vc proof
        let vc_doc_private_keys = credential.did_vc_doc_private_keys;
        let account_doc_verification_pem_bytes = vc_doc_private_keys
            .clone()
            .authentication
            .map(|val| {
                val.decrypt_verification("password".to_string())
                    .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))
            })
            .ok_or(VerifiableError::VCGenerateError(
                "PrivateKeyPairs is missing".to_string(),
            ));
        assert!(!account_doc_verification_pem_bytes.is_err());

        let account_doc_verification_pem_bytes_unwrap =
            account_doc_verification_pem_bytes.unwrap().unwrap();
        let account_doc_verification_pem =
            String::from_utf8(account_doc_verification_pem_bytes_unwrap)
                .map_err(|err| VerifiableError::VCGenerateError(err.to_string()));
        assert!(!account_doc_verification_pem.is_err());

        let account_doc_keypair = KeyPair::from_pem(account_doc_verification_pem.unwrap())
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()));
        assert!(!account_doc_keypair.is_err());

        let (vc_original, proof) = vc.split_proof();
        assert!(proof.is_some());

        let verified = ProofValue::transform_verifier(
            account_doc_keypair.clone().unwrap(),
            vc_original,
            proof.clone().unwrap().proof_value,
        );
        assert!(!verified.is_err());
        assert!(verified.unwrap());

        // verification should be error if using VC directly
        let verified_invalid = ProofValue::transform_verifier(
            account_doc_keypair.unwrap(),
            vc,
            proof.unwrap().proof_value,
        );
        assert!(!verified_invalid.is_err());
        assert!(!verified_invalid.unwrap());
    }

    #[tokio::test]
    async fn test_generate_validation_error() {
        let repo = MockFakeRepo::new();
        let account = MockFakeAccountUsecase::new();
        let rpc = MockFakeRPCClient::new();

        let uc = generate_usecase(repo, rpc, account);

        let cred_value = serde_json::to_value(FakeCredential {
            msg: "hello world".to_string(),
        })
        .unwrap();

        let generate_pass = uc
            .generate_credential(
                "".to_string(),
                "issuer".to_string(),
                cred_value.clone(),
                None,
            )
            .await;
        assert!(generate_pass.is_err());

        let generate_pass_err = generate_pass.unwrap_err();
        assert!(matches!(
            generate_pass_err,
            VerifiableError::ValidationError(_)
        ));

        if let VerifiableError::ValidationError(msg) = generate_pass_err {
            assert!(msg.contains("password"))
        }

        let generate_issuer = uc
            .generate_credential("password".to_string(), "".to_string(), cred_value, None)
            .await;
        assert!(generate_issuer.is_err());

        let generate_issuer_err = generate_issuer.unwrap_err();
        assert!(matches!(
            generate_issuer_err,
            VerifiableError::ValidationError(_)
        ));

        if let VerifiableError::ValidationError(msg) = generate_issuer_err {
            assert!(msg.contains("did_issuer"))
        }
    }

    #[tokio::test]
    async fn test_generate_error_generate_did() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let mut repo = MockFakeRepo::new();
        repo.expect_save_credential().returning(|_| Ok(()));

        let mut account = MockFakeAccountUsecase::new();
        account.expect_clone().times(1).return_once(|| {
            let mut expected = MockFakeAccountUsecase::new();
            expected
                .expect_generate_did()
                .with(eq("password".to_string()))
                .return_once(move |_| {
                    Err(AccountError::UnknownError("error generate".to_string()))
                });

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc, account);

        let cred_value = serde_json::to_value(FakeCredential {
            msg: "hello world".to_string(),
        })
        .unwrap();

        let vc = uc
            .generate_credential(
                "password".to_string(),
                did_issuer_value.clone(),
                cred_value.clone(),
                None,
            )
            .await;
        assert!(vc.is_err());
    }

    #[tokio::test]
    async fn test_generate_error_repo() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save_credential()
                .returning(|_| Err(VerifiableError::RepoError("repo error".to_string())));

            expected
        });

        let mut account = MockFakeAccountUsecase::new();
        account.expect_clone().times(1).return_once(move || {
            let did_vc = did_vc_cloned;

            let mut expected = MockFakeAccountUsecase::new();
            expected
                .expect_generate_did()
                .with(eq("password".to_string()))
                .return_once(move |_| {
                    let did_vc_value_cloned = did_vc.identity().unwrap().value();
                    let did_vc_doc = did_vc.identity().unwrap().to_doc();
                    let did_vc_doc_private_keys = did_vc
                        .identity()
                        .unwrap()
                        .build_private_keys("password".to_string())
                        .unwrap();
                    let did_vc_keysecure = did_vc
                        .account()
                        .privkey()
                        .to_keysecure("password".to_string())
                        .unwrap();

                    Ok(AccountIdentity {
                        id: Uuid::new_v4().to_string(),
                        did: did_vc_value_cloned.clone(),
                        keysecure: did_vc_keysecure,
                        doc: did_vc_doc,
                        doc_private_keys: did_vc_doc_private_keys,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    })
                });

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc, account);

        let cred_value = serde_json::to_value(FakeCredential {
            msg: "hello world".to_string(),
        })
        .unwrap();

        let vc = uc
            .generate_credential(
                "password".to_string(),
                did_issuer_value.clone(),
                cred_value.clone(),
                None,
            )
            .await;
        assert!(vc.is_err());
        assert!(matches!(vc.unwrap_err(), VerifiableError::RepoError(_)))
    }

    #[tokio::test]
    async fn test_vc_send_success() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let vc = VC::new("vc-id".to_string(), did_issuer_value.clone());
        let vc_cloned = vc.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_get_credential_by_id()
                .with(eq("cred-id".to_string()))
                .return_once(move |_| {
                    Ok(Credential {
                        id: "cred-id".to_string(),
                        did: did_issuer_value,
                        did_vc: did_vc.to_owned().identity().unwrap().value(),
                        did_vc_doc_private_keys: did_vc
                            .to_owned()
                            .identity()
                            .unwrap()
                            .build_private_keys("password".to_string())
                            .unwrap(),
                        vc: vc_cloned,
                        keysecure: did_vc_cloned
                            .account()
                            .privkey()
                            .to_keysecure("password".to_string())
                            .unwrap(),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    })
                });

            expected
        });

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let addr_cloned = addr.clone();

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRPCClient::new();
            expected.expect_send_credential_to_holder()
                .with(eq(addr_cloned.clone()), eq(vc))
                .times(1)
                .returning(|_, _| Ok(()));

            expected
        });

        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);
        let send_output = uc
            .send_credential_to_holder("cred-id".to_string(), addr)
            .await;
        assert!(!send_output.is_err())
    }

    #[tokio::test]
    async fn test_vc_send_validation_error() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();

        let uc = generate_usecase(repo, rpc, account);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let send_output = uc.send_credential_to_holder("".to_string(), addr).await;
        assert!(send_output.is_err());

        let send_output_err = send_output.unwrap_err();
        assert!(matches!(
            send_output_err,
            VerifiableError::ValidationError(_)
        ));

        if let VerifiableError::ValidationError(msg) = send_output_err {
            assert!(msg.contains("id"))
        }
    }

    #[tokio::test]
    async fn test_vc_send_error_repo() {
        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_get_credential_by_id()
                .with(eq("cred-id".to_string()))
                .return_once(move |_| Err(VerifiableError::RepoError("error repo".to_string())));

            expected
        });

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();

        let uc = generate_usecase(repo, rpc, account);
        let send_output = uc
            .send_credential_to_holder("cred-id".to_string(), addr)
            .await;
        assert!(send_output.is_err());
        assert!(matches!(
            send_output.unwrap_err(),
            VerifiableError::RepoError(_)
        ))
    }

    #[tokio::test]
    async fn test_vc_send_error_rpc() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let vc = VC::new("vc-id".to_string(), did_issuer_value.clone());
        let vc_cloned = vc.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_get_credential_by_id()
                .with(eq("cred-id".to_string()))
                .return_once(move |_| {
                    Ok(Credential {
                        id: "cred-id".to_string(),
                        did: did_issuer_value,
                        did_vc: did_vc.to_owned().identity().unwrap().value(),
                        did_vc_doc_private_keys: did_vc
                            .to_owned()
                            .identity()
                            .unwrap()
                            .build_private_keys("password".to_string())
                            .unwrap(),
                        vc: vc_cloned,
                        keysecure: did_vc_cloned
                            .account()
                            .privkey()
                            .to_keysecure("password".to_string())
                            .unwrap(),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                    })
                });

            expected
        });

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let addr_cloned = addr.clone();

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRPCClient::new();
            expected.expect_send_credential_to_holder()
                .with(eq(addr_cloned.clone()), eq(vc))
                .times(1)
                .returning(|_, _| Err(VerifiableError::VCSendError("send error".to_string())));

            expected
        });

        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);
        let send_output = uc
            .send_credential_to_holder("cred-id".to_string(), addr)
            .await;
        assert!(send_output.is_err());
        assert!(matches!(
            send_output.unwrap_err(),
            VerifiableError::VCSendError(_)
        ))
    }

    #[tokio::test]
    async fn test_receive_by_holder() {
        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save_credential_holder().returning(|_| Ok(()));

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let vc = VC::new("vc-id".to_string(), did_issuer_value.clone());

        let receive = uc
            .receive_credential_by_holder("request-id-1".to_string(), addr.to_string(), vc)
            .await;
        assert!(!receive.is_err());
    }

    #[tokio::test]
    async fn test_receive_by_holder_validation_error() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);

        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();
        let vc = VC::new("vc-id".to_string(), did_issuer_value.clone());

        let receive_request_id = uc
            .receive_credential_by_holder("".to_string(), "issuer-addr".to_string(), vc.clone())
            .await;
        assert!(receive_request_id.is_err());

        let receive_err_request_id = receive_request_id.unwrap_err();
        assert!(matches!(
            receive_err_request_id.clone(),
            VerifiableError::ValidationError(_)
        ));

        if let VerifiableError::ValidationError(msg) = receive_err_request_id {
            assert!(msg.contains("request_id"))
        }

        let receive_issuer_addr = uc
            .receive_credential_by_holder("request_id".to_string(), "".to_string(), vc)
            .await;
        assert!(receive_issuer_addr.is_err());

        let receive_err_issuer_addr = receive_issuer_addr.unwrap_err();
        assert!(matches!(
            receive_err_issuer_addr.clone(),
            VerifiableError::ValidationError(_)
        ));

        if let VerifiableError::ValidationError(msg) = receive_err_issuer_addr {
            assert!(msg.contains("issuer_addr"))
        }
    }
}
