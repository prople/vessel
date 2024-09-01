use rst_common::with_errors::thiserror::{self, Error};
use rst_common::standard::serde::{self, Serialize, Deserialize};

use prople_did_core::verifiable::objects::Proof;

#[derive(Debug, Error, Clone)]
pub enum ProofError {
    #[error("build proof error: {0}")]
    BuildError(String),
}


#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
/// `ProofParams` used to build our `Verifiable Credential Proof` data object or [`Proof`]
/// This object will be optional used at [`VerifiableUsecaseBuilder::vc_generate`]
pub struct Params {
    pub id: String,
    pub typ: String,
    pub purpose: String,
    pub method: String,
    pub expires: Option<String>,
    pub nonce: Option<String>,
    pub cryptosuite: Option<String>,
}

impl Params {
    pub fn build(&self) -> Proof {
        let proof = Proof::new(self.id.clone());
        proof
    }
}
