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

    #[error("unable to process incoming VP: {0}")]
    ReceiveError(String),

    #[error("unable to verify VP: {0}")]
    VerifyError(String),

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

pub trait VerifierEntityAccessor: Clone {
    fn get_id(&self) -> String;
    fn get_did_verifier(&self) -> String;
    fn get_vp(&self) -> VP;
    fn is_verified(&self) -> bool;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

/// `PresentationAPI` it's a API that should be used as an entrypoint to the
/// `Presentation` logics
#[async_trait]
pub trait PresentationAPI: Clone {
    type PresentationEntityAccessor: PresentationEntityAccessor;
    type VerifierEntityAccessor: VerifierEntityAccessor;

    async fn generate(
        &self,
        password: String,
        did_issuer: String,
        credentials: Vec<String>,
        proof_params: Option<ProofParams>,
    ) -> Result<Self::PresentationEntityAccessor, PresentationError>;

    async fn send_to_verifier(&self, id: String, did_uri: String) -> Result<(), PresentationError>;

    async fn verify_presentation_by_verifier(&self, id: String) -> Result<(), PresentationError>;

    async fn get_by_id(
        &self,
        id: String,
    ) -> Result<Self::PresentationEntityAccessor, PresentationError>;

    async fn receive_presentation_by_verifier(
        &self,
        did_verifier: String,
        vp: VP,
    ) -> Result<(), PresentationError>;

    async fn list_vps_by_did_verifier(
        &self,
        did_verifier: String,
    ) -> Result<Vec<Self::VerifierEntityAccessor>, PresentationError>;
}

/// `RepoBuilder` it's an abstraction used for Presentation's repository data persistent mapper
#[async_trait]
pub trait RepoBuilder: Clone + Sync + Send {
    type PresentationEntityAccessor: PresentationEntityAccessor;
    type VerifierEntityAccessor: VerifierEntityAccessor;

    async fn save_presentation_verifier(
        &self,
        data: &Self::VerifierEntityAccessor,
    ) -> Result<(), PresentationError>;

    async fn set_presentation_verifier_verified(
        &self,
        holder: &Self::VerifierEntityAccessor,
    ) -> Result<(), PresentationError>;

    async fn get_by_id(
        &self,
        id: String,
    ) -> Result<Self::PresentationEntityAccessor, PresentationError>;

    async fn get_verifier_by_id(
        &self,
        id: String,
    ) -> Result<Self::VerifierEntityAccessor, PresentationError>;

    async fn list_vps_by_did_verifier(
        &self,
        did_verifier: String,
    ) -> Result<Vec<Self::VerifierEntityAccessor>, PresentationError>;

    async fn save(&self, data: &Self::PresentationEntityAccessor) -> Result<(), PresentationError>;
}

/// `RpcBuilder` it's an abstraction to cover Presentation's RPC needs
#[async_trait]
pub trait RpcBuilder: Clone + Sync + Send {
    async fn send_to_verifier(&self, did_verifier: String, vp: VP)
        -> Result<(), PresentationError>;
}

/// `UsecaseBuilder` is a main abstraction that should be used by application level controller for the Presentation
/// domain. This usecase abstraction MUST INHERIT the [`PresentationAPI`]
#[async_trait]
pub trait UsecaseBuilder<TPresentationEntity, TVerifierEntity, TAccountEntity>:
    PresentationAPI<
    PresentationEntityAccessor = TPresentationEntity,
    VerifierEntityAccessor = TVerifierEntity,
>
where
    TPresentationEntity: PresentationEntityAccessor,
    TVerifierEntity: VerifierEntityAccessor,
    TAccountEntity: AccountEntityAccessor,
{
    type AccountAPIImplementer: AccountAPI;
    type CredentialAPIImplementer: CredentialAPI;
    type RepoImplementer: RepoBuilder<
        PresentationEntityAccessor = TPresentationEntity,
        VerifierEntityAccessor = TVerifierEntity,
    >;
    type RpcImplementer: RpcBuilder;

    fn account(&self) -> Self::AccountAPIImplementer;
    fn credential(&self) -> Self::CredentialAPIImplementer;
    fn repo(&self) -> Self::RepoImplementer;
    fn rpc(&self) -> Self::RpcImplementer;
}
