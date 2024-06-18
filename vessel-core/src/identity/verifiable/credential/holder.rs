use multiaddr::Multiaddr;

use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::uuid::Uuid;

use prople_did_core::verifiable::objects::VC;

use crate::identity::verifiable::types::VerifiableError;

/// `CredentialHolder` is an entity used by a `Holder` to save incoming [`VC`] that sent
/// from `Issuer`
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Holder {
    pub id: String,
    pub vc: VC,

    #[serde(rename = "requestID")]
    pub request_id: String,

    #[serde(rename = "issuerAddr")]
    pub issuer_addr: Multiaddr,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

impl Holder {
    pub fn new(request_id: String, issuer_addr: String, vc: VC) -> Result<Self, VerifiableError> {
        let uid = Uuid::new_v4().to_string();
        let addr = issuer_addr
            .parse::<Multiaddr>()
            .map_err(|err| VerifiableError::ParseMultiAddrError(err.to_string()))?;

        Ok(Self {
            id: uid,
            vc,
            request_id,
            issuer_addr: addr,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
}
