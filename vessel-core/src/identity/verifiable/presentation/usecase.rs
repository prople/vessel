use rst_common::standard::async_trait::async_trait;

use prople_did_core::did::query::Params as QueryParams;
use prople_did_core::verifiable::objects::VP;

use crate::identity::account::types::AccountAPI;
use crate::identity::account::Account;
use crate::identity::account::URI;

use crate::identity::verifiable::credential::types::CredentialAPI;
use crate::identity::verifiable::types::VerifiableError;
use crate::identity::verifiable::{Credential, Holder};

use super::types::{PresentationAPI, PresentationError, RepoBuilder, RpcBuilder, UsecaseBuilder};
use super::{Presentation, Verifier};

#[derive(Clone)]
pub struct Usecase<TRPCClient, TRepo, TAccountAPI, TCredentialAPI>
where
    TRPCClient: RpcBuilder,
    TRepo:
        RepoBuilder<PresentationEntityAccessor = Presentation, VerifierEntityAccessor = Verifier>,
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
    TRepo:
        RepoBuilder<PresentationEntityAccessor = Presentation, VerifierEntityAccessor = Verifier>,
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

impl<TRPCClient, TRepo, TAccountAPI, TCredentialAPI> UsecaseBuilder<Presentation, Verifier, Account>
    for Usecase<TRPCClient, TRepo, TAccountAPI, TCredentialAPI>
where
    TRPCClient: RpcBuilder,
    TRepo:
        RepoBuilder<PresentationEntityAccessor = Presentation, VerifierEntityAccessor = Verifier>,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
    TCredentialAPI:
        CredentialAPI<EntityAccessor = Credential, HolderEntityAccessor = Holder> + Sync + Send,
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
    TRepo:
        RepoBuilder<PresentationEntityAccessor = Presentation, VerifierEntityAccessor = Verifier>,
    TAccountAPI: AccountAPI<EntityAccessor = Account> + Clone + Sync + Send,
    TCredentialAPI:
        CredentialAPI<EntityAccessor = Credential, HolderEntityAccessor = Holder> + Sync + Send,
{
    type PresentationEntityAccessor = Presentation;
    type VerifierEntityAccessor = Verifier;

    async fn get_by_id(
        &self,
        id: String,
    ) -> Result<Self::PresentationEntityAccessor, PresentationError> {
        self.repo().get_by_id(id).await
    }

    async fn send_presentation(
        &self,
        id: String,
        did_uri: String,
        password: String,
        params: Option<QueryParams>,
    ) -> Result<(), PresentationError> {
        if id.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("id was missing".to_string()),
            ));
        }

        if did_uri.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("did_uri was missing".to_string()),
            ));
        }

        let (uri_addr, _, uri_did) = URI::parse(did_uri).map_err(|err| {
            PresentationError::CommonError(VerifiableError::ParseMultiAddrError(err.to_string()))
        })?;

        let addr = uri_addr.ok_or(PresentationError::CommonError(
            VerifiableError::ParseMultiAddrError("uri address was missing".to_string()),
        ))?;

        let presentation = {
            let presentation_repo = self.repo().get_by_id(id).await?;
            let cloned = presentation_repo.clone();

            match cloned.vp.holder {
                Some(holder) => {
                    let mut presentation_rebuild = presentation_repo.clone();
                    let holder_did_uri = self
                        .account()
                        .build_did_uri(holder.clone(), password.clone(), params)
                        .await
                        .map_err(|err| PresentationError::SendError(err.to_string()))?;

                    presentation_rebuild.vp.set_holder(holder_did_uri);
                    Ok(presentation_rebuild)
                }
                None => Err(PresentationError::SendError(
                    "missing VP holder".to_string(),
                )),
            }
        }?;

        self.rpc()
            .send_to_verifier(addr, uri_did, presentation.vp)
            .await
    }

    async fn generate(
        &self,
        password: String,
        did_issuer: String,
        holder_ids: Vec<String>,
    ) -> Result<Self::PresentationEntityAccessor, PresentationError> {
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

        let holders = self
            .credential()
            .list_holders_by_ids(holder_ids)
            .await
            .map_err(|err| PresentationError::GenerateError(err.to_string()))?;

        let account = self
            .account()
            .get_account_did(did_issuer.clone())
            .await
            .map_err(|err| {
                PresentationError::CommonError(VerifiableError::DIDError(err.to_string()))
            })?;

        let presentation = Presentation::generate(password, did_issuer, account, holders)?;

        let _ = self.repo().save(&presentation.clone()).await?;
        Ok(presentation)
    }

    async fn post_presentation(
        &self,
        did_verifier: String,
        vp: VP,
    ) -> Result<(), PresentationError> {
        if did_verifier.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("did_verifier was missing".to_string()),
            ));
        }

        let _ = self
            .account()
            .get_account_did(did_verifier.clone())
            .await
            .map_err(|err| PresentationError::ReceiveError(err.to_string()))?;

        let presentation_verifier = Verifier::new(did_verifier, vp);
        self.repo()
            .save_presentation_verifier(&presentation_verifier)
            .await
    }

    async fn verify_presentation(&self, id: String) -> Result<(), PresentationError> {
        if id.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("id was missing".to_string()),
            ));
        }

        let repo = self.repo();
        let verifier = repo
            .get_verifier_by_id(id)
            .await
            .map(|vp_verifier| {
                if vp_verifier.is_verified {
                    return Err(PresentationError::VerifyError(
                        "credential already been verified".to_string(),
                    ));
                }

                Ok(vp_verifier)
            })
            .map_err(|err| PresentationError::VerifyError(err.to_string()))??;

        let verifier_verified = verifier.verify_vp(self.account()).await?;
        let _ = repo
            .set_presentation_verifier_verified(&verifier_verified)
            .await?;

        Ok(())
    }

    async fn list_verifiers_by_did(
        &self,
        did_verifier: String,
    ) -> Result<Vec<Self::VerifierEntityAccessor>, PresentationError> {
        if did_verifier.is_empty() {
            return Err(PresentationError::CommonError(
                VerifiableError::ValidationError("did_verifier was missing".to_string()),
            ));
        }

        self.repo().list_verifiers_by_did(did_verifier).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use mockall::predicate::{eq, function};

    use multiaddr::{multiaddr, Multiaddr};

    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::standard::serde_json::value::Value;
    use rst_common::with_tokio::tokio;

    use prople_crypto::eddsa::keypair::KeyPair;
    use prople_crypto::keysecure::types::{Password, ToKeySecure};

    use prople_did_core::did::query::Params as QueryParams;
    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};
    use prople_did_core::hashlink;
    use prople_did_core::keys::{IdentityPrivateKeyPairs, IdentityPrivateKeyPairsBuilder};
    use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
    use prople_did_core::verifiable::objects::{VC, VP};
    use prople_did_core::verifiable::proof::types::Proofable;

    use crate::identity::account::types::{AccountEntityAccessor, AccountError};
    use crate::identity::account::Account as AccountIdentity;
    use crate::identity::verifiable::credential::types::CredentialError;
    use crate::identity::verifiable::credential::Holder;
    use crate::identity::verifiable::proof::builder::Builder as ProofBuilder;
    use crate::identity::verifiable::types::{PaginationParams, VerifiableError};

    use super::Presentation;

    mock!(
        FakeRepo{}

        impl Clone for FakeRepo {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RepoBuilder for FakeRepo {
            type PresentationEntityAccessor = Presentation;
            type VerifierEntityAccessor = Verifier;

            async fn save(&self, data: &Presentation) -> Result<(), PresentationError>;

            async fn save_presentation_verifier(
                &self,
                data: &Verifier,
            ) -> Result<(), PresentationError>;

            async fn set_presentation_verifier_verified(
                &self,
                holder: &Verifier,
            ) -> Result<(), PresentationError>;

            async fn get_verifier_by_id(
                &self,
                id: String,
            ) -> Result<Verifier, PresentationError>;

            async fn list_verifiers_by_did(
                &self,
                did_verifier: String,
            ) -> Result<Vec<Verifier>, PresentationError>;

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
            async fn send_to_verifier(&self, addr: Multiaddr, did_verifier: String, vp: VP) -> Result<(), PresentationError>;
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
            type HolderEntityAccessor = Holder;

            async fn generate_credential(
                &self,
                password: String,
                did_issuer: String,
                credential: Value,
            ) -> Result<Credential, CredentialError>;

            async fn send_credential(
                &self,
                id: String,
                did_uri: String,
                password: String,
                params: Option<QueryParams>
            ) -> Result<(), CredentialError>;

            async fn post_credential(
                &self,
                did_holder: String,
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

            async fn list_holders_by_did(
                &self,
                did: String,
                pagination: Option<PaginationParams>,
            ) -> Result<Vec<Holder>, CredentialError>;

            async fn list_holders_by_ids(
                &self,
                ids: Vec<String>,
            ) -> Result<Vec<Holder>, CredentialError>;
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
        TRepo: RepoBuilder<PresentationEntityAccessor = Presentation, VerifierEntityAccessor = Verifier>,
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
            .to_keysecure(Password::from("password".to_string()))
            .unwrap();

        let did2 = generate_did();
        let did2_keysecure = did2
            .account()
            .privkey()
            .to_keysecure(Password::from("password".to_string()))
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

    fn generate_holders(credentials: Vec<Credential>) -> Vec<Holder> {
        let mut holders = Vec::<Holder>::new();

        for credential in credentials.iter() {
            let did_issuer = generate_did();

            let holder = Holder::new(
                did_issuer.identity().unwrap().value(),
                credential.vc.to_owned(),
            );

            holders.push(holder);
        }

        holders
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

    fn generate_verifier_account() -> (Account, DID) {
        let did_verifier = generate_did();
        let mut did_verifier_identity = did_verifier.identity().unwrap();
        let did_verifier_value = did_verifier_identity.value();

        let did_verifier_doc = did_verifier_identity
            .build_assertion_method()
            .build_auth_method()
            .to_doc();

        let did_verifier_doc_privkeys = did_verifier_identity
            .build_private_keys("password".to_string())
            .unwrap();

        let did_verifier_keysecure = did_verifier
            .account()
            .privkey()
            .to_keysecure(Password::from("password".to_string()))
            .unwrap();

        let did_verifier_account = Account::new(
            did_verifier_value,
            did_verifier_doc,
            did_verifier_doc_privkeys,
            did_verifier_keysecure,
        );

        (did_verifier_account, did_verifier)
    }

    fn generate_verifier(
        addr: Multiaddr,
        password: String,
        vcs: Vec<Credential>,
    ) -> (Verifier, Doc) {
        let did = generate_did();
        let did_value = did.identity().unwrap().value();

        let mut did_identity = did.identity().unwrap();
        did_identity.build_assertion_method().build_auth_method();

        let did_doc = did_identity.to_doc();
        let did_privkeys = did_identity.build_private_keys(password.clone()).unwrap();

        let mut query_params = Params::default();
        query_params.address = Some(addr.to_string());

        let did_uri = did.build_uri(Some(query_params)).unwrap();

        let mut vp = VP::new();
        vp.add_context(CONTEXT_VC.to_string())
            .add_context(CONTEXT_VC_V2.to_string())
            .add_type("VerifiableCredential".to_string())
            .set_holder(did_value.clone());

        for credential in vcs.iter() {
            vp.add_credential(credential.vc.to_owned());
        }

        let secured =
            ProofBuilder::build_proof(vp.clone(), password, did_privkeys.clone()).unwrap();

        vp.setup_proof(secured.unwrap());
        vp.set_holder(did_uri);

        let verifier = Verifier::new(did_value, vp);

        (verifier, did_doc)
    }

    #[tokio::test]
    async fn test_generate() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let did_issuer = generate_did();

        let mut did_issuer_uri_params = Params::default();
        did_issuer_uri_params.address = Some(addr.to_string());

        let did_issuer_uri_builder = did_issuer.build_uri(Some(did_issuer_uri_params));
        assert!(!did_issuer_uri_builder.is_err());

        let did_issuer_uri = did_issuer_uri_builder.unwrap();

        let mut did_issuer_identity = did_issuer.identity().unwrap();
        did_issuer_identity
            .build_assertion_method()
            .build_auth_method();

        let did_issuer_mock = did_issuer.clone();

        let creds = generate_credentials();
        let holders = generate_holders(creds.clone());

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected.expect_save().returning(|_| Ok(()));

            expected
        });

        let mut credential = MockFakeCredentialUsecase::new();
        credential.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeCredentialUsecase::new();
            expected
                .expect_list_holders_by_ids()
                .returning(move |_| Ok(holders.clone()));

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
                    .to_keysecure(Password::from("password".to_string()))
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

        let result = uc
            .generate(
                "password".to_string(),
                did_issuer_uri.clone(),
                vec!["id1".to_string(), "id2".to_string()],
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

        let proof = vp.get_proof();
        assert!(proof.is_some());
    }

    #[tokio::test]
    async fn test_send_to_verifier() {
        let presentation = generate_presentation();
        let presentation_cloned = presentation.clone();
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

        let (verifier_account, verifier_did) = generate_verifier_account();
        let verifier_did_value = verifier_did.identity().unwrap().value();

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let cloned_addr = addr.clone();

        let mut did_uri_params = Params::default();
        did_uri_params.address = Some(addr.clone().to_string());
        did_uri_params.hl = Some(hashlink::generate_from_json(verifier_account.get_doc()).unwrap());

        let did_holder_uri = URI::build(
            verifier_account,
            "password".to_string(),
            Some(did_uri_params),
        )
        .unwrap();

        let expected_presentation = presentation_cloned.clone();
        let expected_presentation_addr = cloned_addr.clone();

        let expected_rpc_presentation = presentation_cloned.clone();
        let expected_rpc_addr = cloned_addr.clone();

        let mut rpc = MockFakeRPCClient::new();
        rpc.expect_clone().times(1).return_once(move || {
            let expected_presentation = expected_rpc_presentation.clone();
            let mut vp = expected_presentation.vp;
            let holder = vp.holder.as_ref().unwrap();

            vp.set_holder(format!("{}?address={}", holder.clone(), expected_rpc_addr));

            let mut expected = MockFakeRPCClient::new();
            expected
                .expect_send_to_verifier()
                .with(eq(addr), eq(verifier_did_value), eq(vp.clone()))
                .times(1)
                .returning(|_, _, _| Ok(()));

            expected
        });

        let mut account = MockFakeAccountUsecase::new();
        account.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeAccountUsecase::new();
            let vp = expected_presentation.vp;
            let holder = vp.holder.unwrap();

            expected
                .expect_build_did_uri()
                .with(
                    eq(holder.clone()),
                    eq("password".to_string()),
                    function(|val: &Option<QueryParams>| val.is_some()),
                )
                .times(1)
                .return_once(move |_, _, _| {
                    let vp_did = format!(
                        "{}?address={}",
                        holder.clone(),
                        expected_presentation_addr.clone()
                    );
                    Ok(vp_did)
                });

            expected
        });

        let credential = MockFakeCredentialUsecase::new();

        let uc = generate_usecase(repo, rpc, account, credential);
        let send_output = uc
            .send_presentation(
                "id1".to_string(),
                did_holder_uri,
                "password".to_string(),
                Some(QueryParams {
                    address: Some(cloned_addr.clone().to_string()),
                    hl: None,
                }),
            )
            .await;
        assert!(!send_output.is_err())
    }

    #[tokio::test]
    async fn test_send_to_verifier_validation_error() {
        let repo = MockFakeRepo::new();
        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();
        let credential = MockFakeCredentialUsecase::new();

        let uc = generate_usecase(repo, rpc, account, credential);

        let (verifier_account, _) = generate_verifier_account();
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let mut did_uri_params = Params::default();
        did_uri_params.address = Some(addr.clone().to_string());
        did_uri_params.hl = Some(hashlink::generate_from_json(verifier_account.get_doc()).unwrap());

        let did_holder_uri = URI::build(
            verifier_account,
            "password".to_string(),
            Some(did_uri_params),
        )
        .unwrap();

        let send_output = uc
            .send_presentation("".to_string(), did_holder_uri, "password".to_string(), None)
            .await;
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

        let (verifier_account, _) = generate_verifier_account();

        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);

        let mut did_uri_params = Params::default();
        did_uri_params.address = Some(addr.clone().to_string());
        did_uri_params.hl = Some(hashlink::generate_from_json(verifier_account.get_doc()).unwrap());

        let did_holder_uri = URI::build(
            verifier_account,
            "password".to_string(),
            Some(did_uri_params),
        )
        .unwrap();

        let send_output = uc
            .send_presentation(
                "id1".to_string(),
                did_holder_uri,
                "password".to_string(),
                None,
            )
            .await;
        assert!(send_output.is_err());

        let send_output_err = send_output.unwrap_err();
        assert!(matches!(send_output_err, PresentationError::CommonError(_)));
    }

    #[tokio::test]
    async fn test_receive() {
        let (verifier_account, verifier_did) = generate_verifier_account();
        let verifier_did_value = verifier_did.identity().unwrap().value();

        let presentation = generate_presentation();

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let mut expected = MockFakeRepo::new();
            expected
                .expect_save_presentation_verifier()
                .times(1)
                .returning(|_| Ok(()));

            expected
        });

        let mut account = MockFakeAccountUsecase::new();
        account.expect_clone().times(1).return_once(move || {
            let verifier_account = verifier_account.clone();
            let mut expected = MockFakeAccountUsecase::new();
            expected
                .expect_get_account_did()
                .returning(move |_| Ok(verifier_account.clone()));

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let credential = MockFakeCredentialUsecase::new();

        let uc = generate_usecase(repo, rpc, account, credential);

        let output = uc
            .post_presentation(verifier_did_value, presentation.vp)
            .await;

        assert!(!output.is_err());
    }

    #[tokio::test]
    async fn test_receive_by_verifier_validation_error() {
        let repo = MockFakeRepo::new();
        let account = MockFakeAccountUsecase::new();
        let rpc = MockFakeRPCClient::new();
        let credential = MockFakeCredentialUsecase::new();

        let presentation = generate_presentation();
        let uc = generate_usecase(repo, rpc, account, credential);

        let vp = presentation.vp;
        let output = uc.post_presentation("".to_string(), vp.clone()).await;
        assert!(output.is_err());

        let send_output_err = output.unwrap_err();
        assert!(matches!(send_output_err, PresentationError::CommonError(_)));
        if let PresentationError::CommonError(msg) = send_output_err {
            assert!(msg.to_string().contains("did_verifier"))
        }
    }

    #[tokio::test]
    async fn test_list_vps_by_did_verifier() {
        let p1 = generate_presentation();
        let p2 = generate_presentation();

        let did_verifier = generate_did();
        let did_verifier_value = did_verifier.identity().unwrap().value();
        let did_verifier_value_cloned = did_verifier_value.clone();

        let v1 = Verifier::new(did_verifier_value.clone(), p1.vp);

        let v2 = Verifier::new(did_verifier_value.clone(), p2.vp);

        let verifiers = vec![v1, v2];

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(move || {
            let verifiers = verifiers.clone();

            let mut expected = MockFakeRepo::new();
            expected
                .expect_list_verifiers_by_did()
                .with(eq(did_verifier_value_cloned))
                .times(1)
                .return_once(move |_| Ok(verifiers));

            expected
        });

        let account = MockFakeAccountUsecase::new();
        let rpc = MockFakeRPCClient::new();
        let credential = MockFakeCredentialUsecase::new();

        let uc = generate_usecase(repo, rpc, account, credential);
        let output = uc.list_verifiers_by_did(did_verifier_value).await;
        assert!(!output.is_err());
        assert_eq!(output.unwrap().len(), 2)
    }

    #[tokio::test]
    async fn test_list_vps_by_did_verifier_validation_error() {
        let repo = MockFakeRepo::new();
        let account = MockFakeAccountUsecase::new();
        let rpc = MockFakeRPCClient::new();
        let credential = MockFakeCredentialUsecase::new();

        let uc = generate_usecase(repo, rpc, account, credential);
        let output = uc.list_verifiers_by_did("".to_string()).await;
        assert!(output.is_err());

        let send_output_err = output.unwrap_err();
        assert!(matches!(send_output_err, PresentationError::CommonError(_)));

        if let PresentationError::CommonError(msg) = send_output_err {
            assert!(msg.to_string().contains("did_verifier"))
        }
    }

    #[tokio::test]
    async fn test_verify_presentation_by_verifier() {
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let credentials = generate_credentials();
        let (verifier, doc) =
            generate_verifier(addr, String::from("password".to_string()), credentials);

        let mut repo = MockFakeRepo::new();
        repo.expect_clone().times(1).return_once(|| {
            let mut expected = MockFakeRepo::new();

            expected
                .expect_set_presentation_verifier_verified()
                .times(1)
                .returning(|holder| {
                    assert!(holder.is_verified);
                    Ok(())
                });

            expected
                .expect_get_verifier_by_id()
                .times(1)
                .with(eq("id-holder".to_string()))
                .return_once(move |_| Ok(verifier.clone()));

            expected
        });

        let mut account = MockFakeAccountUsecase::new();
        account.expect_clone().times(1).return_once(|| {
            let mut expected = MockFakeAccountUsecase::new();

            expected
                .expect_resolve_did_uri()
                .times(1)
                .return_once(move |_| Ok(doc.clone()));

            expected
        });

        let rpc = MockFakeRPCClient::new();
        let credential = MockFakeCredentialUsecase::new();

        let uc = generate_usecase(repo, rpc, account, credential);
        let verify_vp_checker = uc.verify_presentation("id-holder".to_string()).await;

        assert!(!verify_vp_checker.is_err());
    }
}
