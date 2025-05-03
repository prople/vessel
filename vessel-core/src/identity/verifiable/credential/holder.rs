use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_did_core::verifiable::objects::VC;

use super::types::{CredentialError, HolderEntityAccessor};

/// `CredentialHolder` is an entity used by a `Holder` to save incoming [`VC`] that sent
/// from `Issuer`
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct Holder {
    pub(crate) id: String,
    pub(crate) did_holder: String,
    pub(crate) vc: VC,

    #[serde(rename = "isVerified")]
    pub(crate) is_verified: bool,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
}

impl Holder {
    pub fn new(did_holder: String, vc: VC) -> Self {
        let uid = Uuid::new_v4().to_string();
        Self {
            id: uid,
            did_holder,
            vc,
            is_verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn set_verified(&mut self) -> &mut Self {
        self.is_verified = true;
        self
    }
}

impl ToJSON for Holder {
    fn to_json(&self) -> Result<String, BaseError> {
        let json_str =
            serde_json::to_string(&self).map_err(|err| BaseError::ToJSONError(err.to_string()))?;

        Ok(json_str)
    }
}

impl TryInto<Vec<u8>> for Holder {
    type Error = CredentialError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let json = serde_json::to_vec(&self)
            .map_err(|err| CredentialError::GenerateJSONError(err.to_string()))?;
        Ok(json)
    }
}

impl TryFrom<Vec<u8>> for Holder {
    type Error = CredentialError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let holder: Holder = serde_json::from_slice(&value)
            .map_err(|err| CredentialError::UnserializeError(err.to_string()))?;
        Ok(holder)
    }
}

impl HolderEntityAccessor for Holder {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_vc(&self) -> VC {
        self.vc.to_owned()
    }

    fn get_is_verified(&self) -> bool {
        self.is_verified.to_owned()
    }

    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at.to_owned()
    }

    fn get_updated_at(&self) -> DateTime<Utc> {
        self.updated_at.to_owned()
    }

    fn get_did_holder(&self) -> String {
        self.did_holder.to_owned()
    }
}
