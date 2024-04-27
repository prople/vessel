use multiaddr::Multiaddr;

use rst_common::standard::serde_json::Value;
use rst_common::standard::uuid::Uuid;

use prople_crypto::eddsa::keypair::KeyPair;

use prople_did_core::account::Account;
use prople_did_core::types::{CONTEXT_VC, CONTEXT_VC_V2};
use prople_did_core::verifiable::objects::{Proof, ProofValue, VC};

use crate::identity::account::types::{AccountUsecaseBuilder, AccountUsecaseEntryPoint};
use crate::identity::verifiable::types::{
    Credential, VerifiableError, VerifiableRPCBuilder, VerifiableRepoBuilder,
    VerifiableUsecaseBuilder,
};

use super::types::ProofParams;

pub struct Usecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder,
    TRepo: VerifiableRepoBuilder,
    TAccount: AccountUsecaseBuilder + Clone,
{
    repo: TRepo,
    rpc: TRPCClient,
    account: TAccount,
}

impl<TRPCClient, TRepo, TAccount> Usecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder,
    TRepo: VerifiableRepoBuilder,
    TAccount: AccountUsecaseBuilder + Clone,
{
    pub fn new(repo: TRepo, rpc: TRPCClient, account: TAccount) -> Self {
        Self { repo, rpc, account }
    }
}

impl<TRPCClient, TRepo, TAccount> AccountUsecaseEntryPoint for Usecase<TRPCClient, TRepo, TAccount>
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

impl<TRPCClient, TRepo, TAccount> VerifiableUsecaseBuilder for Usecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder,
    TRepo: VerifiableRepoBuilder,
    TAccount: AccountUsecaseBuilder + Clone,
{
    fn vc_generate(
        &self,
        password: String,
        did_issuer: String,
        credential: Value,
        proof_params: Option<ProofParams>,
    ) -> Result<Credential, VerifiableError> {
        let account = self
            .account()
            .generate_did(password.clone())
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let account_keysecure = account.clone().keysecure;
        let account_did = Account::from_keysecure(password, account_keysecure.clone())
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let account_pem = account_did
            .build_pem()
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let account_keypair = KeyPair::from_pem(account_pem)
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let mut vc = VC::new(account.did.clone(), did_issuer.clone());
        vc.add_context(CONTEXT_VC.to_string())
            .add_context(CONTEXT_VC_V2.to_string())
            .add_type("VerifiableCredential".to_string())
            .set_credential(credential);

        if let Some(params) = proof_params {
            let proof_value = ProofValue::from_jcs(account_keypair, vc.clone())
                .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

            let uid = Uuid::new_v4().to_string();
            let mut proof = Proof::new(uid);
            proof.typ(params.typ);
            proof.purpose(params.purpose);
            proof.method(params.method);
            proof.signature(proof_value);

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

        let cred = Credential::new(did_issuer, vc, account_keysecure);
        let _ = self
            .repo
            .save(cred.clone())
            .map_err(|err| VerifiableError::RepoError(err.to_string()))?;

        Ok(cred)
    }

    fn vc_confirm(&self, _id: String) -> Result<(), VerifiableError> {
        Ok(())
    }

    fn vc_lists(&self, _did: String) -> Result<Vec<Credential>, VerifiableError> {
        Ok(vec![])
    }

    fn vc_receive(&self, _id: String, _vc: VC) -> Result<(), VerifiableError> {
        Ok(())
    }

    fn vc_send(&self, id: String, receiver: Multiaddr) -> Result<(), VerifiableError> {
        let cred = self.repo.get_by_id(id)?;
        self.rpc.vc_send_to(receiver, cred.vc)
    }

    fn vc_verify_by_issuer(&self, _vc: VC) -> Result<(), VerifiableError> {
        Ok(())
    }

    fn vc_verify_by_verifier(&self, _uri: String, _vc: VC) -> Result<(), VerifiableError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use mockall::predicate::eq;
    use multiaddr::{multiaddr, Multiaddr};

    use prople_crypto::keysecure::types::ToKeySecure;
    use prople_did_core::did::{query::Params, DID};
    use prople_did_core::doc::types::{Doc, ToDoc};

    use rst_common::standard::chrono::Utc;
    use rst_common::standard::serde::{self, Deserialize, Serialize};
    use rst_common::standard::serde_json;

    use crate::identity::account::types::{Account as AccountIdentity, AccountError};

    mock!(
        FakeRepo{}

        impl VerifiableRepoBuilder for FakeRepo {
            fn save(&self, data: Credential) -> Result<(), VerifiableError>;
            fn remove_by_id(&self, id: String) -> Result<(), VerifiableError>;
            fn remove_by_did(&self, did: String) -> Result<(), VerifiableError>;
            fn get_by_did(&self, did: String) -> Result<Credential, VerifiableError>;
            fn get_by_id(&self, id: String) -> Result<Credential, VerifiableError>;
            fn list_by_did(&self, did: String) -> Result<Vec<Credential>, VerifiableError>;
            fn list_all(&self, limit: u32, offset: u32) -> Result<Vec<Credential>, VerifiableError>;
        }
    );

    mock!(
        FakeRPCClient{}

        impl VerifiableRPCBuilder for FakeRPCClient {
            fn vc_send_to(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
            fn vc_verify_to(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
        }
    );

    mock!(
        FakeAccountUsecase{}

        impl Clone for FakeAccountUsecase {
            fn clone(&self) -> Self;
        }

        impl AccountUsecaseBuilder for FakeAccountUsecase {

            fn generate_did(&self, password: String) -> Result<AccountIdentity, AccountError>;
            fn build_did_uri(
                &self,
                did: String,
                password: String,
                params: Option<Params>,
            ) -> Result<String, AccountError>;
            fn resolve_did_uri(&self, uri: String) -> Result<Doc, AccountError>;
            fn resolve_did_doc(&self, did: String) -> Result<Doc, AccountError>;
            fn remove_did(&self, did: String) -> Result<(), AccountError>;
            fn get_account_did(&self, did: String) -> Result<AccountIdentity, AccountError>;
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
    ) -> Usecase<TRPCClient, TRepo, TAccount> {
        Usecase::new(repo, rpc, account)
    }

    fn generate_did() -> DID {
        DID::new()
    }

    #[test]
    fn test_generate_success_without_params() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_save().returning(|_| Ok(()));

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
        );
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

    #[test]
    fn test_generate_success_with_params() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_save().returning(|_| Ok(()));

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
        );
        assert!(!vc.is_err());

        let credential = vc.unwrap();
        assert!(credential.vc.proof.is_some());
        assert_eq!(credential.did, did_issuer_value);
        assert_eq!(credential.vc.issuer, did_issuer_value);
        assert_eq!(credential.vc.id, did_vc.identity().unwrap().value());

        let vc_types = credential.vc.types;
        assert_eq!(vc_types.len(), 1);
        assert_eq!(vc_types[0], "VerifiableCredential".to_string());

        let vc_cred = credential.vc.credential_subject;
        assert_eq!(vc_cred, cred_value)
    }

    #[test]
    fn test_generate_error_generate_did() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let mut repo = MockFakeRepo::new();
        repo.expect_save().returning(|_| Ok(()));

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
        );
        assert!(vc.is_err());
    }

    #[test]
    fn test_generate_error_repo() {
        let did_issuer = generate_did();
        let did_issuer_value = did_issuer.identity().unwrap().value();

        let did_vc = generate_did();
        let did_vc_cloned = did_vc.clone();

        let mut repo = MockFakeRepo::new();
        repo.expect_save()
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
        );
        assert!(vc.is_err());
        assert!(matches!(vc.unwrap_err(), VerifiableError::RepoError(_)))
    }

    #[test]
    fn test_vc_send_success() {
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
        rpc.expect_vc_send_to()
            .with(eq(addr.clone()), eq(vc))
            .times(1)
            .returning(|_, _| Ok(()));

        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);
        let send_output = uc.vc_send("cred-id".to_string(), addr);
        assert!(!send_output.is_err())
    }

    #[test]
    fn test_vc_send_error_repo() { 
        let mut repo = MockFakeRepo::new();
        repo.expect_get_by_id()
            .with(eq("cred-id".to_string()))
            .return_once(move |_| {
                Err(VerifiableError::RepoError("error repo".to_string()))
            });
        
        let addr = multiaddr!(Ip4([127, 0, 0, 1]), Udp(10500u16), QuicV1);
        let rpc = MockFakeRPCClient::new();
        let account = MockFakeAccountUsecase::new();
        
        let uc = generate_usecase(repo, rpc, account);
        let send_output = uc.vc_send("cred-id".to_string(), addr);
        assert!(send_output.is_err());
        assert!(matches!(send_output.unwrap_err(), VerifiableError::RepoError(_)))
    }

    #[test]
    fn test_vc_send_error_rpc() {
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
        rpc.expect_vc_send_to()
            .with(eq(addr.clone()), eq(vc))
            .times(1)
            .returning(|_, _| Err(VerifiableError::VCSendError("send error".to_string())));
        
        let account = MockFakeAccountUsecase::new();
        let uc = generate_usecase(repo, rpc, account);
        let send_output = uc.vc_send("cred-id".to_string(), addr);
        assert!(send_output.is_err());
        assert!(matches!(send_output.unwrap_err(), VerifiableError::VCSendError(_)))
    }
}
