use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use prople_vessel_rpc::components::presentation::CorePresentationModel;

use crate::models::identity::account::types::DID;
use crate::models::types::{AgentName, Key, KeyIdentifier, Model, ModelError, ValueBuilder};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct Presentation {
    id: String,
    did: DID,
    presentation: CorePresentationModel,
}

impl TryFrom<Vec<u8>> for Presentation {
    type Error = ModelError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let jsonstr = String::from_utf8(value)
            .map_err(|err| ModelError::DeserializeError(err.to_string()))?;

        let deserialized = serde_json::from_str::<Presentation>(&jsonstr)
            .map_err(|err| ModelError::DeserializeError(err.to_string()))?;

        Ok(deserialized)
    }
}

impl Presentation {
    pub fn new(id: String, did: DID, presentation: CorePresentationModel) -> Self {
        Self {
            id,
            did,
            presentation,
        }
    }

    pub fn get_did(&self) -> DID {
        self.did.to_owned()
    }
}

impl KeyIdentifier for Presentation {
    fn key_name(&self, agent: AgentName) -> Key {
        let key = format!(
            "{}_presentation_{}",
            agent.to_string(),
            self.get_did().to_string()
        );

        Key::from(key)
    }
}

impl ValueBuilder for Presentation {}
impl Model for Presentation {}
