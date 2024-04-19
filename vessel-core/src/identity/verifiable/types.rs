use multiaddr::Multiaddr;

use rst_common::with_errors::thiserror::{self, Error};

use rst_common::standard::uuid::Uuid;
use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};

use rst_common::standard::serde::{self, Serialize, Deserialize};
use rst_common::standard::serde_json::value::Value;

use prople_did_core::verifiable::objects::VC;

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
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct VCData {
    pub id: String,
    pub did: String,
    pub vc: VC,
    
    #[serde(with = "ts_seconds")]
    pub created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

impl VCData {
    pub fn new(did: String, vc: VC) -> Self {
        Self { 
            id: Uuid::new_v4().to_string(), 
            did, 
            vc, 
            created_at: Utc::now(), 
            updated_at: Utc::now() 
        }
    }
}

pub trait VerifiableUsecaseBuilder {
    fn vc_generate(&self, did: String, credential: Value) -> Result<VCData, VerifiableError>; 
    fn vc_send(&self, id: String) -> Result<(), VerifiableError>;
    fn vc_receive(&self, id: String, vc: VC) -> Result<(), VerifiableError>;
    fn vc_confirm(&self, id: String) -> Result<(), VerifiableError>;
    fn vc_verify_by_verifier(&self, uri: String, vc: VC) -> Result<(), VerifiableError>;
    fn vc_verify_by_issuer(&self, vc: VC) -> Result<(), VerifiableError>;
    fn vc_lists(&self, did: String) -> Result<Vec<VCData>, VerifiableError>;
} 

pub trait VerifiableRepoBuilder {
    fn save(&self, data: VCData) -> Result<(), VerifiableError>;
    fn remove_by_id(&self, id: String) -> Result<(), VerifiableError>;
    fn remove_by_did(&self, did: String) -> Result<(), VerifiableError>;
    fn get_by_did(&self, did: String) -> Result<VCData, VerifiableError>;
    fn get_by_id(&self, id: String) -> Result<VCData, VerifiableError>;
    fn list_by_did(&self, did: String) -> Result<Vec<VCData>, VerifiableError>;
    fn list_all(&self, limit: u32, offset: u32) -> Result<Vec<VCData>, VerifiableError>;
}

pub trait VerifiableRPCBuilder {
    fn vc_send_to(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
    fn vc_verify_to(&self, addr: Multiaddr, vc: VC) -> Result<(), VerifiableError>;
}