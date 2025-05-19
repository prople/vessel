use multiaddr::Multiaddr;
use std::fmt::Debug;

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::with_errors::thiserror::{self, Error};

use rstdev_domain::entity::ToJSON;

use prople_did_core::did::query::Params as QueryParams;
use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::verifiable::objects::VP;

use crate::identity::account::types::{AccountAPI, AccountEntityAccessor};
use crate::identity::verifiable::credential::types::CredentialAPI;
use crate::identity::verifiable::types::VerifiableError;

pub const VP_TYPE: &str = "VerifiablePresentation";

/// PresentationError is a base error types for the `Presentation` domain 
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub enum PresentationError {
    #[error("unable to generate vp: {0}")]
    GenerateError(String),

    #[error("json error: {0}")]
    GenerateJSONError(String),

    #[error("unable to process incoming VP: {0}")]
    ReceiveError(String),

    #[error("unable to verify VP: {0}")]
    VerifyError(String),

    #[error("unable unserialize account: {0}")]
    UnserializeError(String),

    #[error("presentation not found")]
    PresentationNotFound,

    #[error("verifier not found")]
    VerifierNotFound,

    #[error("list presentation error: {0}")]
    ListError(String),

    #[error("holder not found")]
    HolderNotFound,

    #[error("common error")]
    CommonError(#[from] VerifiableError),

    #[error("send presentation error")]
    SendError(String),
}

/// `PresentationEntityAccessor` is a getter object used to access
/// all `Presentation` property fields
pub trait PresentationEntityAccessor:
    Clone + Debug + ToJSON + TryInto<Vec<u8>> + TryFrom<Vec<u8>>
{
    fn get_id(&self) -> String;
    fn get_vp(&self) -> VP;
    fn get_private_keys(&self) -> IdentityPrivateKeyPairs;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

/// `VerifierEntityAccessor` is a getter object used to access all `Verifier` property fields
pub trait VerifierEntityAccessor:
    Clone + Debug + ToJSON + TryInto<Vec<u8>> + TryFrom<Vec<u8>>
{
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

    /// `generate` is method used to generate a new `Presentation` object
    /// this method will depends on the list of `credentials` that passed 
    async fn generate(
        &self,
        password: String,
        did_issuer: String,
        credentials: Vec<String>,
    ) -> Result<Self::PresentationEntityAccessor, PresentationError>;

    /// `send_presentation` is method used to send the `Presentation` object
    /// to some `verifier` address
    async fn send_presentation(
        &self,
        id: String,
        did_uri: String,
        password: String,
        params: Option<QueryParams>,
    ) -> Result<(), PresentationError>;

    /// `verify_presentation` is method used to verify the `Presentation` object
    /// This method should be used by a `verifier` to verify the `Presentation`
    async fn verify_presentation(&self, id: String) -> Result<(), PresentationError>;

    /// `get_by_id` is method used to get the `Presentation` object by id from persistent storage
    async fn get_by_id(
        &self,
        id: String,
    ) -> Result<Self::PresentationEntityAccessor, PresentationError>;

    /// `post_presentation` is method used to save incoming `Presentation` object
    /// This method should be used by a `verifier` to save the incoming `Presentation`
    /// 
    /// This method will generate the `Verifier` object and save it to the persistent storage
    async fn post_presentation(
        &self,
        did_verifier: String,
        vp: VP,
    ) -> Result<(), PresentationError>;

    /// `list_vps_by_did_verifier` is method used to list all saved `Presentation` object
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
    /// `send_to_verifier` is method used to send the `Presentation` object
    /// It need the `did_verifier` which is a `DID URI` belongs to the `verifier`
    async fn send_to_verifier(
        &self,
        addr: Multiaddr,
        did_verifier: String,
        vp: VP,
    ) -> Result<(), PresentationError>;
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
