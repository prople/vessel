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
        did_cred: String,
        credential: Value,
        proof_params: Option<ProofParams>,
    ) -> Result<Credential, VerifiableError> {
        let account = self
            .account()
            .get_account_did(did_cred.clone())
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let account_keysecure = account.clone().keysecure;
        let account_did = Account::from_keysecure(password, account_keysecure.clone())
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let account_pem = account_did
            .build_pem()
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let account_keypair = KeyPair::from_pem(account_pem)
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        let mut vc = VC::new(did_cred.clone(), did_issuer);
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

        let cred = Credential::new(did_cred, vc, account_keysecure);
        let _ = self
            .repo
            .save(cred.clone())
            .map_err(|err| VerifiableError::VCGenerateError(err.to_string()))?;

        Ok(cred)
    }

    fn vc_confirm(&self, id: String) -> Result<(), VerifiableError> {
        Ok(())
    }

    fn vc_lists(&self, did: String) -> Result<Vec<Credential>, VerifiableError> {
        Ok(vec![])
    }

    fn vc_receive(&self, id: String, vc: VC) -> Result<(), VerifiableError> {
        Ok(())
    }

    fn vc_send(&self, id: String) -> Result<(), VerifiableError> {
        Ok(())
    }

    fn vc_verify_by_issuer(&self, vc: VC) -> Result<(), VerifiableError> {
        Ok(())
    }

    fn vc_verify_by_verifier(&self, uri: String, vc: VC) -> Result<(), VerifiableError> {
        Ok(())
    }
}
