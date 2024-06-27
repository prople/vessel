use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::uuid::Uuid;

use prople_did_core::verifiable::objects::VP;

use super::types::VerifierEntityAccessor;

/// `CredentialHolder` is an entity used by a `Holder` to save incoming [`VC`] that sent
/// from `Issuer`
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Verifier {
    pub(crate) id: String,
    pub(crate) did_verifier: String,
    pub(crate) vp: VP,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
}

impl Verifier {
    pub fn new(
        did_verifier: String,
        vp: VP,
    ) -> Self {
        let uid = Uuid::new_v4().to_string();
        Self {
            id: uid,
            did_verifier,
            vp,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl VerifierEntityAccessor for Verifier {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_vp(&self) -> VP {
        self.vp.to_owned()
    }

    fn get_did_verifier(&self) -> String {
        self.did_verifier.to_owned()
    }

    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at.to_owned()
    }

    fn get_updated_at(&self) -> DateTime<Utc> {
        self.updated_at.to_owned()
    }
}
