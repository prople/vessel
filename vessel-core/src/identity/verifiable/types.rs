use multiaddr::Multiaddr;

use rst_common::with_errors::thiserror::{self, Error};

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::uuid::Uuid;

use rst_common::standard::serde::{self, Deserialize, Serialize};

use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::verifiable::objects::{VC, VP};

use super::proof::types::Params as ProofParams;
use super::Credential;
use crate::identity::account::types::UsecaseImplementer as AccountUsecaseImplementer;

pub const VP_TYPE: &str = "VerifiablePresentation";

#[derive(Debug, Error, Clone)]
pub enum VerifiableError {
    #[error("did error: {0}")]
    DIDError(String),

    #[error("unable to generate vc: {0}")]
    VCGenerateError(String),

    #[error("unable to process incoming vc: {0}")]
    VCReceiveError(String),

    #[error("unable to send vc: {0}")]
    VCSendError(String),

    #[error("unable to confirm vc: {0}")]
    VCConfirmError(String),

    #[error("unable to verify vc: {0}")]
    VCVerifyError(String),

    #[error("unable to list vc: {0}")]
    VCListError(String),

    #[error("unable to generate vp: {0}")]
    VPGenerateError(String),

    #[error("repo error: {0}")]
    RepoError(String),

    #[error("parse multiaddr error: {0}")]
    ParseMultiAddrError(String),

    #[error("validaiton error: {0}")]
    ValidationError(String),

    #[error("unknown error: {0}")]
    UnknownError(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Presentation {
    pub id: String,
    pub vp: VP,
    pub private_keys: IdentityPrivateKeyPairs,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl Presentation {
    pub fn new(vp: VP, private_keys: IdentityPrivateKeyPairs) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            vp,
            private_keys,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// `PaginationParams` used when we need to load a list of something from persistent storage
/// it assumed using common pagination params contains of page, limit and skip
pub struct PaginationParams {
    pub page: usize,
    pub limit: usize,
    pub skip: usize,
}

#[async_trait]
pub trait VerifiablePresentationUsecaseBuilder: AccountUsecaseImplementer {
    async fn vp_generate(
        &self,
        password: String,
        did_issuer: String,
        credentials: Vec<String>,
        proof_params: Option<ProofParams>,
    ) -> Result<Presentation, VerifiableError>;

    async fn vp_send_to_verifier(
        &self,
        id: String,
        receiver: Multiaddr,
    ) -> Result<(), VerifiableError>;

    async fn vp_lists(
        &self,
        id: String,
        pagination: Option<PaginationParams>,
    ) -> Result<Vec<Presentation>, VerifiableError>;
}

#[async_trait]
pub trait VerifiableRepoBuilder {
    async fn save_credential(&self, data: Credential) -> Result<(), VerifiableError>;
    async fn save_presentation(&self, data: Presentation) -> Result<(), VerifiableError>;
    async fn remove_by_id(&self, id: String) -> Result<(), VerifiableError>;
    async fn remove_by_did(&self, did: String) -> Result<(), VerifiableError>;

    async fn get_vp_by_id(&self, id: String) -> Result<Presentation, VerifiableError>;
    async fn get_by_did(&self, did: String) -> Result<Credential, VerifiableError>;
    async fn get_by_id(&self, id: String) -> Result<Credential, VerifiableError>;
    async fn list_vc_by_ids(&self, ids: Vec<String>) -> Result<Vec<Credential>, VerifiableError>;
    async fn list_vp_by_id(
        &self,
        ids: String,
        pagination: Option<PaginationParams>,
    ) -> Result<Vec<Presentation>, VerifiableError>;

    async fn list_vc_by_did(
        &self,
        did: String,
        pagination: Option<PaginationParams>,
    ) -> Result<Vec<Credential>, VerifiableError>;
}

pub trait VerifiableRPCBuilder {
    fn vc_send_to_holder(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
    fn vc_verify_to_issuer(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
    fn vp_send_to_verifier(&self, addr: Multiaddr, vp: VP) -> Result<(), VerifiableError>;
}
