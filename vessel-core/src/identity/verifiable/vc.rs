use multiaddr::Multiaddr;

use rst_common::standard::serde_json::Value;
use rst_common::standard::uuid::Uuid;
use rst_common::standard::async_trait::async_trait;

use prople_crypto::eddsa::keypair::KeyPair;

use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
use prople_did_core::verifiable::objects::{Proof, ProofValue, VC};

use super::types::{
    Credential, CredentialHolder, PaginationParams, ProofParams,
    VerifiableCredentialUsecaseBuilder, VerifiableError, VerifiableRPCBuilder,
    VerifiableRepoBuilder,
};
use crate::identity::account::types::{AccountUsecaseBuilder, AccountUsecaseImplementer};

pub struct CredentialUsecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder,
    TRepo: VerifiableRepoBuilder,
    TAccount: AccountUsecaseBuilder + Clone,
{
    repo: TRepo,
    rpc: TRPCClient,
    account: TAccount,
}

impl<TRPCClient, TRepo, TAccount> CredentialUsecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder,
    TRepo: VerifiableRepoBuilder,
    TAccount: AccountUsecaseBuilder + Clone,
{
    pub fn new(repo: TRepo, rpc: TRPCClient, account: TAccount) -> Self {
        Self { repo, rpc, account }
    }
}

impl<TRPCClient, TRepo, TAccount> AccountUsecaseImplementer
    for CredentialUsecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder,
    TRepo: VerifiableRepoBuilder,
    TAccount: AccountUsecaseBuilder + Clone,
{
    type Implementer = TAccount;

    fn account(&self) -> Self::Implementer {
        self.account.clone()
    }
}

#[async_trait]
impl<TRPCClient, TRepo, TAccount> VerifiableCredentialUsecaseBuilder
    for CredentialUsecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder + Sync,
    TRepo: VerifiableRepoBuilder + Sync,
    TAccount: AccountUsecaseBuilder + Clone + Sync + Send,
{
    async fn vc_generate(
        &self,
        password: String,
        did_issuer: String,
        credential: Value,
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

        let account = self
            .account()
            .generate_did(password.clone()).await
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let account_did = account.clone().did;
        let account_keysecure = account.clone().keysecure;
        let account_doc_private_key_pairs = account.doc_private_keys;

        let mut vc = VC::new(account.did.clone(), did_issuer.clone());
        vc.add_context(CONTEXT_VC.to_string())
            .add_context(CONTEXT_VC_V2.to_string())
            .add_type("VerifiableCredential".to_string())
            .set_credential(credential);

        if let Some(params) = proof_params {
            let account_doc_password = password.clone();
            let account_doc_verification_pem_bytes = account_doc_private_key_pairs
                .clone()
                .authentication
                .map(|val| {
                    val.decrypt_verification(account_doc_password.clone())
                        .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))
                })
                .ok_or(VerifiableError::VCGenerateError(
                    "PrivateKeyPairs is missing".to_string(),
                ))??;

            let account_doc_verification_pem =
                String::from_utf8(account_doc_verification_pem_bytes)
                    .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

            let account_doc_keypair = KeyPair::from_pem(account_doc_verification_pem)
                .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

            let (_, sig) = ProofValue::transform(account_doc_keypair, vc.clone())
                .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

            let uid = Uuid::new_v4().to_string();
            let mut proof = Proof::new(uid);
            proof.typ(params.typ);
            proof.purpose(params.purpose);
            proof.method(params.method);
            proof.set_signature_as_string(sig);

            if let Some(cryptosuite) = params.cryptosuite {
                proof.cryptosuite(cryptosuite);
            }

            if let Some(nonce) = params.nonce {
                proof.nonce(nonce);
            }

            if let Some(expiry) = params.expires {
                proof.expires(expiry);
            }

            vc.proof(proof);
        }

        let cred = Credential::new(
            did_issuer,
            account_did,
            account_doc_private_key_pairs,
            vc,
            account_keysecure,
        );
        let _ = self
            .repo
            .save_credential(cred.clone()).await
            .map_err(|err| VerifiableError::RepoError(err.to_string()))?;

        Ok(cred)
    }

    async fn vc_lists(
        &self,
        did: String,
        pagination: Option<PaginationParams>,
    ) -> Result<Vec<Credential>, VerifiableError> {
        self.repo.list_vc_by_did(did, pagination).await
    }

    async fn vc_receive_by_holder(
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

        let cred_holder = CredentialHolder::new(request_id, issuer_addr, vc)?;
        self.repo.save_credential_holder(cred_holder).await
    }

    async fn vc_send_to_holder(&self, id: String, receiver: Multiaddr) -> Result<(), VerifiableError> {
        if id.is_empty() {
            return Err(VerifiableError::ValidationError(
                "id was missing".to_string(),
            ));
        }

        let cred = self.repo.get_by_id(id).await?;
        self.rpc.vc_send_to_holder(receiver, cred.vc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use mockall::predicate::eq;

    use rst_common::standard::chrono::Utc;
    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::standard::serde_json;
    use rst_common::standard::async_trait::async_trait;
    use rst_common::with_tokio::tokio;

    use multiaddr::{multiaddr, Multiaddr};

    use prople_crypto::keysecure::types::ToKeySecure;

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::keys::IdentityPrivateKeyPairsBuilder;
    use prople_did_core::verifiable::objects::VP;

    use crate::identity::account::types::AccountError;
    use crate::identity::account::Account as AccountIdentity;
    use crate::identity::verifiable::types::Presentation;

    mock!(
        FakeRepo{}

        #[async_trait]
        impl VerifiableRepoBuilder for FakeRepo {
            async fn save_credential(&self, data: Credential) -> Result<(), VerifiableError>;
            async fn save_presentation(&self, data: Presentation) -> Result<(), VerifiableError>;
            async fn save_credential_holder(&self, data: CredentialHolder) -> Result<(), VerifiableError>;
            async fn remove_by_id(&self, id: String) -> Result<(), VerifiableError>;
            async fn remove_by_did(&self, did: String) -> Result<(), VerifiableError>;
            async fn get_by_did(&self, did: String) -> Result<Credential, VerifiableError>;
            async fn get_by_id(&self, id: String) -> Result<Credential, VerifiableError>;
            async fn list_vc_by_ids(&self, ids: Vec<String>) -> Result<Vec<Credential>, VerifiableError>;
            async fn list_vc_by_did(&self, did: String, pagination: Option<PaginationParams>) -> Result<Vec<Credential>, VerifiableError>;
            async fn list_vp_by_id(&self, ids: String, pagination: Option<PaginationParams>) -> Result<Vec<Presentation>, VerifiableError>;
            async fn get_vp_by_id(&self, id: String) -> Result<Presentation, VerifiableError>;
        }
    );

    mock!(
        FakeRPCClient{}

        impl VerifiableRPCBuilder for FakeRPCClient {
            fn vc_send_to_holder(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
            fn vc_verify_to_issuer(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
            fn vp_send_to_verifier(&self, addr: Multiaddr, vp: VP) -> Result<(), VerifiableError>;
        }
    );

    mock!(
        FakeAccountUsecase{}

        impl Clone for FakeAccountUsecase {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl AccountUsecaseBuilder for FakeAccountUsecase {

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
        TRepo: VerifiableRepoBuilder,
        TRPCClient: VerifiableRPCBuilder,
        TAccount: AccountUsecaseBuilder + Clone,
    >(
        repo: TRepo,
        rpc: TRPCClient,
        account: TAccount,
    ) -> CredentialUsecase<TRPCClient, TRepo, TAccount> {
        CredentialUsecase::new(repo, rpc, account)
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
        repo.expect_save_credential().returning(|_| Ok(()));

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

        let vc = uc.vc_generate(
            "password".to_string(),
            did_issuer_value.clone(),
            cred_value.clone(),
            None,
        ).await;
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
        repo.expect_save_credential().returning(|_| Ok(()));

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

        let vc = uc.vc_generate(
            "password".to_string(),
            did_issuer_value.clone(),
            cred_value.clone(),
            Some(proof_params),
        ).await;
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

        let generate_pass = uc.vc_generate(
            "".to_string(),
            "issuer".to_string(),
            cred_value.clone(),
            None,
        ).await;
        assert!(generate_pass.is_err());

        let generate_pass_err = generate_pass.unwrap_err();
        assert!(matches!(
            generate_pass_err,
            VerifiableError::ValidationError(_)
        ));

        if let VerifiableError::ValidationError(msg) = generate_pass_err {
            assert!(msg.contains("password"))
        }

        let generate_issuer =
            uc.vc_generate("password".to_string(), "".to_string(), cred_value, None).await;
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

        let vc = uc.vc_generate(
            "password".to_string(),
            did_issuer_value.clone(),
            cred_value.clone(),
            None,
        ).await;
        assert!(vc.is_err());
    }

    #[tokio::test]
    async fn test_generate_error_repo() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_save_credential()
            .returning(|_| Err(VerifiableError::RepoError("repo error".to_string())));

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

        let vc = uc.vc_generate(
            "password".to_string(),
            did_issuer_value.clone(),
            cred_value.clone(),
            None,
        ).await;
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
        repo.expect_get_by_id()
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

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_vc_send_to_holder()
            .with(eq(addr.clone()), eq(vc))
            .times(1)
            .returning(|_, _| Ok(()));

        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);
        let send_output = uc.vc_send_to_holder("cred-id".to_string(), addr).await;
        assert!(!send_output.is_err())
    }

    #[tokio::test]
    async fn test_vc_send_validation_error() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();

        let uc = generate_usecase(repo, rpc, account);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let send_output = uc.vc_send_to_holder("".to_string(), addr).await;
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
        repo.expect_get_by_id()
            .with(eq("cred-id".to_string()))
            .return_once(move |_| Err(VerifiableError::RepoError("error repo".to_string())));

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();

        let uc = generate_usecase(repo, rpc, account);
        let send_output = uc.vc_send_to_holder("cred-id".to_string(), addr).await;
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
        repo.expect_get_by_id()
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

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_vc_send_to_holder()
            .with(eq(addr.clone()), eq(vc))
            .times(1)
            .returning(|_, _| Err(VerifiableError::VCSendError("send error".to_string())));

        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);
        let send_output = uc.vc_send_to_holder("cred-id".to_string(), addr).await;
        assert!(send_output.is_err());
        assert!(matches!(
            send_output.unwrap_err(),
            VerifiableError::VCSendError(_)
        ))
    }

    #[tokio::test]
    async fn test_receive_by_holder() {
        let mut repo = MockFakeRepo::new();
        repo.expect_save_credential_holder().returning(|_| Ok(()));

        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let vc = VC::new("vc-id".to_string(), did_issuer_value.clone());

        let receive = uc.vc_receive_by_holder("request-id-1".to_string(), addr.to_string(), vc).await;
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

        let receive_request_id =
            uc.vc_receive_by_holder("".to_string(), "issuer-addr".to_string(), vc.clone()).await;
        assert!(receive_request_id.is_err());

        let receive_err_request_id = receive_request_id.unwrap_err();
        assert!(matches!(
            receive_err_request_id.clone(),
            VerifiableError::ValidationError(_)
        ));

        if let VerifiableError::ValidationError(msg) = receive_err_request_id {
            assert!(msg.contains("request_id"))
        }

        let receive_issuer_addr =
            uc.vc_receive_by_holder("request_id".to_string(), "".to_string(), vc).await;
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
