use prople_crypto::eddsa::keypair::KeyPair;

use prople_did_core::account::Account;
use prople_did_core::types::CONTEXT_VC_V2;
use prople_did_core::verifiable::objects::{Proof, ProofValue, VP};

use crate::identity::account::types::{AccountUsecaseBuilder, AccountUsecaseEntryPoint};

use super::types::{
    Presentation, VerifiableError, VerifiablePresentationUsecaseBuilder, VerifiableRPCBuilder,
    VerifiableRepoBuilder, VP_TYPE,
};

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

impl<TRPCClient, TRepo, TAccount> AccountUsecaseEntryPoint
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

impl<TRPCClient, TRepo, TAccount> VerifiablePresentationUsecaseBuilder
    for PresentationUsecase<TRPCClient, TRepo, TAccount>
where
    TRPCClient: VerifiableRPCBuilder,
    TRepo: VerifiableRepoBuilder,
    TAccount: AccountUsecaseBuilder + Clone,
{
    fn vp_generate(
        &self,
        password: String,
        did_issuer: String,
        credentials: Vec<String>,
    ) -> Result<Presentation, VerifiableError> {
        let vcs = self
            .repo
            .list_vc_by_id(credentials)
            .map_err(|err| VerifiableError::RepoError(err.to_string()))?;

        let mut vp = VP::new();
        vp.add_context(CONTEXT_VC_V2.to_string());
        vp.add_type(String::from(VP_TYPE.to_string()));
        vp.set_holder(did_issuer);

        for credential in vcs.iter() {
            let credential_keysecure = credential.keysecure.to_owned();
            let credential_did = Account::from_keysecure(password.clone(), credential_keysecure)
                .map_err(|err| VerifiableError::VPGenerateError(err.to_string()))?;

            let credential_pem = credential_did
                .build_pem()
                .map_err(|err| VerifiableError::VPGenerateError(err.to_string()))?;

            let credential_keypair = KeyPair::from_pem(credential_pem)
                .map_err(|err| VerifiableError::VPGenerateError(err.to_string()))?;

            let credential_keypair = vp.add_credential(credential.vc.to_owned());
        }

        Err(VerifiableError::UnknownError(String::from(
            "not implemented",
        )))
    }
}
