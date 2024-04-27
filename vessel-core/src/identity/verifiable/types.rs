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

/// `Credential` is a main entity used to save to internal persistent storage
/// This data must contain a [`VC`] and [`KeySecure`]
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

/// `ProofParams` used to build our `Verifiable Credential Proof` data object or [`Proof`]
/// This object will be optional used at [`VerifiableUsecaseBuilder::vc_generate`]
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

/// `VerifiableUsecaseBuilder` is a main trait to build the usecase business logic
/// for the `Verifiable` domain. This trait will inherit trait behaviors from [`AccountUsecaseEntryPoint`]
/// this mean, the implementer need to define the `Implementer` type and define how to
/// get the `AccountUsecase` object
///
/// This trait will maintain all logic that relate with the `VC (Verifiable Credential)` and also
/// `VP (Verifiable Presentation)`
pub trait VerifiableUsecaseBuilder: AccountUsecaseEntryPoint {
    /// `vc_generate` used to generate the `Verifiable Credential` and [`Credential`] object
    /// entity. The generated credential entity should be saved into persistent storage through
    /// our implementer of [`VerifiableRepoBuilder`]
    ///
    /// The `credential` is an object of [`Value`], it can be anything that able to convert to `serde_json::value::Value`
    /// The `proof_params` is an optional parameter, if an user want to generate a `VC` with its [`Proof`], it must
    /// be set, but if not, just left it `None`
    fn vc_generate(
        &self,
        password: String,
        did_issuer: String,
        credential: Value,
        proof_params: Option<ProofParams>,
    ) -> Result<Credential, VerifiableError>;

    /// `vc_send` used to send a `VC` to some `Holder`, if there is no error it means the `VC`
    /// already received successfully.
    ///
    /// The communiation itself must be happened through [`VerifiableRPCBuilder::vc_send_to`], the implementation
    /// of this RPC client must call the RPC method of `vc.receive` belongs to `Holder`
    ///
    /// The `VC` that need to send to the `Holder` should be loaded from our persistent storage
    /// based on given `id` which is the id of [`Credential`]
    fn vc_send(&self, id: String, receiver: Multiaddr) -> Result<(), VerifiableError>;
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
