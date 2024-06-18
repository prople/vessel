use rst_common::standard::async_trait::async_trait;
use rst_common::standard::uuid::Uuid;

use prople_crypto::eddsa::keypair::KeyPair;

use prople_did_core::types::CONTEXT_VC_V2;
use prople_did_core::verifiable::objects::{Proof, ProofValue, VP};

use crate::identity::account::types::{AccountUsecaseBuilder, AccountUsecaseImplementer};

use super::types::{
    Presentation, VerifiableError, VerifiablePresentationUsecaseBuilder, VerifiableRPCBuilder,
    VerifiableRepoBuilder, VP_TYPE,
};

use super::proof::types::Params as ProofParams;

pub struct PresentationUsecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder,
    TRepo: VerifiableRepoBuilder,
    TAccount: AccountUsecaseBuilder + Clone,
{
    repo: TRepo,
    rpc: TRPCClient,
    account: TAccount,
}

impl<TRPCClient, TRepo, TAccount> PresentationUsecase<TRPCClient, TRepo, TAccount>
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
    for PresentationUsecase<TRPCClient, TRepo, TAccount>
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
impl<TRPCClient, TRepo, TAccount> VerifiablePresentationUsecaseBuilder
    for PresentationUsecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder + Sync,
    TRepo: VerifiableRepoBuilder + Sync,
    TAccount: AccountUsecaseBuilder + Clone + Sync + Send,
{
    async fn vp_generate(
        &self,
        password: String,
        did_issuer: String,
        credentials: Vec<String>,
        proof_params: Option<ProofParams>,
    ) -> Result<Presentation, VerifiableError> {
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

        let vcs = self
            .repo
            .list_vc_by_ids(credentials)
            .await
            .map_err(|err| VerifiableError::RepoError(err.to_string()))?;

        let mut vp = VP::new();
        vp.add_context(CONTEXT_VC_V2.to_string())
            .add_type(String::from(VP_TYPE.to_string()))
            .set_holder(did_issuer.clone());

        for credential in vcs.iter() {
            vp.add_credential(credential.vc.to_owned());
        }

        let account = self
            .account()
            .get_account_did(did_issuer)
            .await
            .map_err(|err| VerifiableError::DIDError(err.to_string()))?;

        let account_doc_private_key_pairs = account.doc_private_keys;

        if let Some(params) = proof_params {
            let account_doc_password = password.clone();
            let account_doc_verification_pem_bytes = account_doc_private_key_pairs
                .clone()
                .authentication
                .map(|val| {
                    val.decrypt_verification(account_doc_password.clone())
                        .map_err(|err| VerifiableError::DIDError(err.to_string()))
                })
                .ok_or(VerifiableError::DIDError(
                    "PrivateKeyPairs is missing".to_string(),
                ))??;

            let account_doc_verification_pem =
                String::from_utf8(account_doc_verification_pem_bytes)
                    .map_err(|err| VerifiableError::DIDError(err.to_string()))?;

            let account_doc_keypair = KeyPair::from_pem(account_doc_verification_pem)
                .map_err(|err| VerifiableError::DIDError(err.to_string()))?;

            let (_, sig) = ProofValue::transform(account_doc_keypair, vp.clone())
                .map_err(|err| VerifiableError::DIDError(err.to_string()))?;

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

            vp.add_proof(proof);
        }

        let presentation = Presentation::new(vp, account_doc_private_key_pairs);
        let _ = self.repo.save_presentation(presentation.clone()).await?;

        Ok(presentation)
    }

    async fn vp_send_to_verifier(
        &self,
        id: String,
        receiver: multiaddr::Multiaddr,
    ) -> Result<(), VerifiableError> {
        if id.is_empty() {
            return Err(VerifiableError::ValidationError(
                "id was missing".to_string(),
            ));
        }

        let presentation = self.repo.get_vp_by_id(id).await?;
        self.rpc.vp_send_to_verifier(receiver, presentation.vp)
    }

    async fn vp_lists(
        &self,
        id: String,
        pagination: Option<super::types::PaginationParams>,
    ) -> Result<Vec<Presentation>, VerifiableError> {
        self.repo.list_vp_by_id(id, pagination).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use mockall::predicate::eq;

    use multiaddr::{multiaddr, Multiaddr};

    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::with_tokio::tokio;

    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::keys::{IdentityPrivateKeyPairs, IdentityPrivateKeyPairsBuilder};
    use prople_did_core::verifiable::objects::VC;

    use prople_crypto::keysecure::types::ToKeySecure;

    use crate::identity::account::types::AccountError;
    use crate::identity::account::Account as AccountIdentity;
    use crate::identity::verifiable::types::{CredentialHolder, PaginationParams};
    use crate::identity::verifiable::Credential;

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
    ) -> PresentationUsecase<TRPCClient, TRepo, TAccount> {
        PresentationUsecase::new(repo, rpc, account)
    }

    fn generate_did() -> DID {
        DID::new()
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

    #[tokio::test]
    async fn test_generate_success_without_params() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();
        let did_issuer_mock = did_issuer.clone();

        let creds = generate_credentials();

        let mut repo = MockFakeRepo::new();
        repo.expect_save_presentation().returning(|_| Ok(()));
        repo.expect_list_vc_by_ids()
            .returning(move |_| Ok(creds.clone()));

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

        let rpc = MockFakeRPCClient::new();
        let uc = generate_usecase(repo, rpc, account);

        let result = uc
            .vp_generate(
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
    async fn test_generate_success_with_params() {
        let did_issuer = generate_did();

        let mut did_issuer_identity = did_issuer.identity().unwrap();
        did_issuer_identity
            .build_assertion_method()
            .build_auth_method();

        let did_issuer_value = did_issuer_identity.value();
        let did_issuer_mock = did_issuer.clone();

        let creds = generate_credentials();

        let mut repo = MockFakeRepo::new();
        repo.expect_save_presentation().returning(|_| Ok(()));
        repo.expect_list_vc_by_ids()
            .returning(move |_| Ok(creds.clone()));

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
        let uc = generate_usecase(repo, rpc, account);

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
            .vp_generate(
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
    async fn test_send_to_verifier_success() {
        let presentation = generate_presentation();
        let presentation_mock = presentation.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_get_vp_by_id()
            .with(eq("id1".to_string()))
            .returning(move |_| Ok(presentation_mock.clone()));

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_vp_send_to_verifier()
            .with(eq(addr.clone()), eq(presentation.vp))
            .times(1)
            .returning(|_, _| Ok(()));

        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);

        let send_output = uc.vp_send_to_verifier("id1".to_string(), addr).await;
        assert!(!send_output.is_err())
    }

    #[tokio::test]
    async fn test_send_to_verifier_validation_error() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();

        let uc = generate_usecase(repo, rpc, account);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let send_output = uc.vp_send_to_verifier("".to_string(), addr).await;
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
    async fn test_send_to_verifier_error_repo() {
        let mut repo = MockFakeRepo::new();
        repo.expect_get_vp_by_id()
            .with(eq("id1".to_string()))
            .returning(move |_| Err(VerifiableError::RepoError("error repo".to_string())));

        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();

        let uc = generate_usecase(repo, rpc, account);
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let send_output = uc.vp_send_to_verifier("id1".to_string(), addr).await;
        assert!(send_output.is_err());

        let send_output_err = send_output.unwrap_err();
        assert!(matches!(send_output_err, VerifiableError::RepoError(_)));
    }
}
