use multiaddr::Multiaddr;

use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::uuid::Uuid;

use prople_did_core::verifiable::objects::VC;

use super::types::HolderEntityAccessor;
use crate::identity::verifiable::types::VerifiableError;

/// `CredentialHolder` is an entity used by a `Holder` to save incoming [`VC`] that sent
/// from `Issuer`
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Holder {
    pub(crate) id: String,
    pub(crate) vc: VC,

    #[serde(rename = "requestID")]
    pub(crate) request_id: String,

    #[serde(rename = "issuerAddr")]
    pub(crate) issuer_addr: Multiaddr,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
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

impl HolderEntityAccessor for Holder {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_vc(&self) -> VC {
        self.vc.to_owned()
    }

    fn get_issuer_addr(&self) -> Multiaddr {
        self.issuer_addr.to_owned()
    }

    fn get_request_id(&self) -> String {
        self.request_id.to_owned()
    }

    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at.to_owned()
    }

    fn get_updated_at(&self) -> DateTime<Utc> {
        self.updated_at.to_owned()
    }
}
