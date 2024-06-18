use prople_did_core::verifiable::objects::Proof;

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
