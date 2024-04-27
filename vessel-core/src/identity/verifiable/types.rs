use multiaddr::Multiaddr;

use rst_common::with_errors::thiserror::{self, Error};

use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::uuid::Uuid;

use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json::value::Value;

use prople_crypto::keysecure::KeySecure;
use prople_did_core::verifiable::objects::{Proof, VC};

use crate::identity::account::types::AccountUsecaseEntryPoint;

#[derive(Debug, Error)]
pub enum VerifiableError {
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

    #[error("repo error: {0}")]
    RepoError(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Credential {
    pub id: String,
    pub did: String,
    pub vc: VC,
    pub keysecure: KeySecure,

    #[serde(with = "ts_seconds")]
    pub created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

impl Credential {
    pub fn new(did: String, vc: VC, keysecure: KeySecure) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            keysecure,
            did,
            vc,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

pub struct ProofParams {
    pub id: String,
    pub typ: String,
    pub purpose: String,
    pub method: String,
    pub expires: Option<String>,
    pub nonce: Option<String>,
    pub cryptosuite: Option<String>,
}

impl ProofParams {
    pub fn build(&self) -> Proof {
        let proof = Proof::new(self.id.clone());
        proof
    }
}

pub trait VerifiableUsecaseBuilder: AccountUsecaseEntryPoint {
    fn vc_generate(
        &self,
        password: String,
        did_issuer: String,
        credential: Value,
        proof_params: Option<ProofParams>,
    ) -> Result<Credential, VerifiableError>;

    fn vc_send(&self, id: String) -> Result<(), VerifiableError>;
    fn vc_receive(&self, id: String, vc: VC) -> Result<(), VerifiableError>;
    fn vc_confirm(&self, id: String) -> Result<(), VerifiableError>;
    fn vc_verify_by_verifier(&self, uri: String, vc: VC) -> Result<(), VerifiableError>;
    fn vc_verify_by_issuer(&self, vc: VC) -> Result<(), VerifiableError>;
    fn vc_lists(&self, did: String) -> Result<Vec<Credential>, VerifiableError>;
}

pub trait VerifiableRepoBuilder {
    fn save(&self, data: Credential) -> Result<(), VerifiableError>;
    fn remove_by_id(&self, id: String) -> Result<(), VerifiableError>;
    fn remove_by_did(&self, did: String) -> Result<(), VerifiableError>;
    fn get_by_did(&self, did: String) -> Result<Credential, VerifiableError>;
    fn get_by_id(&self, id: String) -> Result<Credential, VerifiableError>;
    fn list_by_did(&self, did: String) -> Result<Vec<Credential>, VerifiableError>;
    fn list_all(&self, limit: u32, offset: u32) -> Result<Vec<Credential>, VerifiableError>;
}

pub trait VerifiableRPCBuilder {
    fn vc_send_to(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
    fn vc_verify_to(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
}
