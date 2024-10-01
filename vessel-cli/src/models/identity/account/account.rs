use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;

use prople_did_core::doc::types::Doc;

use crate::models::types::{AgentName, Key, KeyIdentifier, Model, ModelError, Value, ValueBuilder};

use super::types::DID;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct Account {
    id: String,
    uri: Option<String>,
    did: DID,
    doc: Option<Doc>,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            id: "".to_string(),
            uri: None,
            did: DID::default(),
            doc: None,
        }
    }
}

impl TryFrom<Vec<u8>> for Account {
    type Error = ModelError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let jsonstr = String::from_utf8(value)
            .map_err(|err| ModelError::DeserializeError(err.to_string()))?;

        let deserialized = serde_json::from_str::<Account>(&jsonstr)
            .map_err(|err| ModelError::DeserializeError(err.to_string()))?;

        Ok(deserialized)
    }
}

impl Account {
    pub fn new(id: String, did: DID, doc: Doc) -> Self {
        Self {
            id,
            uri: None,
            did,
            doc: Some(doc),
        }
    }

    pub fn set_uri(&mut self, uri: String) -> &mut Self {
        self.uri = Some(uri);
        self
    }

    pub fn set_doc(&mut self, doc: Doc) -> &mut Self {
        self.doc = Some(doc);
        self
    }

    pub fn set_did(&mut self, did: DID) -> &mut Self {
        self.did = did;
        self
    }

    pub fn get_id(&self) -> String {
        self.id.to_owned()
    }

    pub fn get_did(&self) -> DID {
        self.did.to_owned()
    }

    pub fn get_uri(&self) -> Option<String> {
        self.uri.to_owned()
    }

    pub fn get_doc(&self) -> Option<Doc> {
        self.doc.to_owned()
    }
}

impl KeyIdentifier for Account {
    fn key_name(&self, agent: AgentName) -> Key {
        let key = format!(
            "{}_account_{}",
            agent.to_string(),
            self.get_did().to_string()
        );

        Key::from(key)
    }
}

impl ValueBuilder for Account {
    fn build_value(&self) -> Result<Value, ModelError> {
        let json = serde_json::to_string(self)
            .map_err(|err| ModelError::BuildValueError(err.to_string()))?;

        Ok(Value::from(json))
    }
}

impl Model for Account {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_default() {
        let account = Account::default();
        assert!(account.get_did().to_string().is_empty());
        assert!(account.get_doc().is_none());
        assert!(account.get_id().to_string().is_empty());
        assert!(account.get_uri().is_none());
    }

    #[test]
    fn test_setup_default() {
        let mut account = Account::default();
        account.set_did(DID::from("did:prople:testing"));

        assert!(!account.get_did().to_string().is_empty());
        assert_eq!(account.get_did().to_string(), "did:prople:testing");

        account.set_uri(String::from("test-uri"));
        assert!(!account.get_uri().is_none());
        assert_eq!(account.get_uri().unwrap(), "test-uri");

        let doc = Doc::generate(String::from("did:prople:testing"));
        account.set_doc(doc);
        assert!(!account.get_doc().is_none());
    }

    #[test]
    fn test_value() {
        let mut account = Account::default();

        let doc = Doc::generate(String::from("did:prople:testing"));
        account
            .set_did(DID::from("did:prople:testing"))
            .set_uri(String::from("test-uri"))
            .set_doc(doc);

        let try_value = account.build_value();
        assert!(!try_value.is_err());

        let value = try_value.unwrap();
        let try_reaccount = Account::try_from(value.to_vec());
        assert!(!try_reaccount.is_err());

        let reaccount = try_reaccount.unwrap();
        let revalue = reaccount.build_value().unwrap();
        assert_eq!(revalue.to_bytes(), value.to_bytes())
    }

    #[test]
    fn test_key() {
        let mut account = Account::default();

        let doc = Doc::generate(String::from("did:prople:testing"));
        account
            .set_did(DID::from("did:prople:testing"))
            .set_uri(String::from("test-uri"))
            .set_doc(doc);

        let key = account.key_name(AgentName::from("agent_test"));
        let try_key_str = String::from_utf8(key.to_vec());
        assert!(!try_key_str.is_err());
        assert_eq!(try_key_str.unwrap(), "agent_test_account_did:prople:testing")
    }

    #[test]
    fn test_model() {
        let mut account = Account::default();

        let doc = Doc::generate(String::from("did:prople:testing"));
        account
            .set_did(DID::from("did:prople:testing"))
            .set_uri(String::from("test-uri"))
            .set_doc(doc);

        let try_model = account.build(AgentName::from("agent_test"));
        assert!(!try_model.is_err());

        let (key, value) = try_model.unwrap();
        
        let try_key_str = String::from_utf8(key.to_vec());
        assert!(!try_key_str.is_err());
        assert_eq!(try_key_str.unwrap(), "agent_test_account_did:prople:testing");
        
        let try_reaccount = Account::try_from(value.to_vec());
        assert!(!try_reaccount.is_err());

        let reaccount = try_reaccount.unwrap();
        let revalue = reaccount.build_value().unwrap();
        assert_eq!(revalue.to_bytes(), value.to_bytes())
    }
}
