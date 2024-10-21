use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use prople_vessel_rpc::components::credential::CoreCredentialModel;

use crate::models::identity::account::types::DID;
use crate::models::types::{AgentName, Key, KeyIdentifier, Model, ModelError, ValueBuilder};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct Credential {
    id: String,
    did: DID,
    credential: CoreCredentialModel,
}

impl TryFrom<Vec<u8>> for Credential {
    type Error = ModelError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let jsonstr = String::from_utf8(value)
            .map_err(|err| ModelError::DeserializeError(err.to_string()))?;

        let deserialized = serde_json::from_str::<Credential>(&jsonstr)
            .map_err(|err| ModelError::DeserializeError(err.to_string()))?;

        Ok(deserialized)
    }
}

impl Credential {
    pub fn new(id: String, did: DID, credential: CoreCredentialModel) -> Self {
        Self {
            id,
            did,
            credential,
        }
    }

    pub fn get_id(&self) -> String {
        self.id.to_owned()
    }

    pub fn get_did(&self) -> DID {
        self.did.to_owned()
    }

    pub fn get_credential(&self) -> CoreCredentialModel {
        self.credential.to_owned()
    }
}

impl KeyIdentifier for Credential {
    fn key_name(&self, agent: AgentName) -> Key {
        let key = format!(
            "{}_credential_{}",
            agent.to_string(),
            self.get_did().to_string()
        );

        Key::from(key)
    }
}

impl ValueBuilder for Credential {}
impl Model for Credential {}
