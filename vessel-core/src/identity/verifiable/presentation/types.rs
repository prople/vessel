use multiaddr::Multiaddr;

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::with_errors::thiserror::{self, Error};

use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::verifiable::objects::VP;

use crate::identity::account::types::{AccountAPI, AccountEntityAccessor};
use crate::identity::verifiable::credential::types::CredentialAPI;
use crate::identity::verifiable::proof::types::Params as ProofParams;
use crate::identity::verifiable::types::VerifiableError;

pub const VP_TYPE: &str = "VerifiablePresentation";

#[derive(Debug, Error, Clone)]
pub enum PresentationError {
    #[error("unable to generate vp: {0}")]
    GenerateError(String),

    #[error("common error")]
    CommonError(#[from] VerifiableError),
}

/// `PresentationEntityAccessor` is a getter object used to access
/// all `Presentation` property fields
pub trait PresentationEntityAccessor: Clone {
    fn get_id(&self) -> String;
    fn get_vp(&self) -> VP;
    fn get_private_keys(&self) -> IdentityPrivateKeyPairs;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

#[async_trait]
pub trait PresentationAPI: Clone {
    type EntityAccessor: PresentationEntityAccessor;

    async fn generate(
        &self,
        password: String,
        did_issuer: String,
        credentials: Vec<String>,
        proof_params: Option<ProofParams>,
    ) -> Result<Self::EntityAccessor, PresentationError>;

    async fn send_to_verifier(
        &self,
        id: String,
        receiver: Multiaddr,
    ) -> Result<(), PresentationError>;

    async fn get_by_id(&self, id: String) -> Result<Self::EntityAccessor, PresentationError>;
}

#[async_trait]
pub trait RepoBuilder: Clone + Sync + Send {
    type EntityAccessor: PresentationEntityAccessor;

    async fn save(&self, data: &Self::EntityAccessor) -> Result<(), PresentationError>;
    async fn get_by_id(&self, id: String) -> Result<Self::EntityAccessor, PresentationError>;
}

#[async_trait]
pub trait RpcBuilder: Clone + Sync + Send {
    async fn send_to_verifier(&self, addr: Multiaddr, vp: VP) -> Result<(), PresentationError>;
}

#[async_trait]
pub trait UsecaseBuilder<TPresentationEntity, TAccountEntity>:
    PresentationAPI<EntityAccessor = TPresentationEntity>
where
    TPresentationEntity: PresentationEntityAccessor,
    TAccountEntity: AccountEntityAccessor,
{
    type AccountAPIImplementer: AccountAPI;
    type CredentialAPIImplementer: CredentialAPI;
    type RepoImplementer: RepoBuilder<EntityAccessor = TPresentationEntity>;
    type RpcImplementer: RpcBuilder;

    fn account(&self) -> Self::AccountAPIImplementer;
    fn credential(&self) -> Self::CredentialAPIImplementer;
    fn repo(&self) -> Self::RepoImplementer;
    fn rpc(&self) -> Self::RpcImplementer;
}
