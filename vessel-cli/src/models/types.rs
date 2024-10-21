use rst_common::standard::serde::Serialize;
use rst_common::standard::serde_json;
use rst_common::with_errors::thiserror::{self, Error};

#[derive(Clone, Debug, Error)]
pub enum ModelError {
    #[error("error value: {0}")]
    BuildValueError(String),

    #[error("error deserialize: {0}")]
    DeserializeError(String),

    #[error("error database: {0}")]
    DatabaseError(String),
}

#[derive(Clone, Debug)]
pub struct AgentName(String);

impl From<&str> for AgentName {
    fn from(value: &str) -> Self {
        AgentName(String::from(value))
    }
}

impl From<String> for AgentName {
    fn from(value: String) -> Self {
        AgentName(value)
    }
}

impl ToString for AgentName {
    fn to_string(&self) -> String {
        self.0.to_owned()
    }
}

#[derive(Clone, Debug)]
pub struct Key(Vec<u8>);

impl From<String> for Key {
    fn from(value: String) -> Self {
        Key(value.as_bytes().to_vec())
    }
}

impl TryInto<String> for Key {
    type Error = ModelError;

    fn try_into(self) -> Result<String, Self::Error> {
        let str = String::from_utf8(self.0)
            .map_err(|err| ModelError::DeserializeError(err.to_string()))?;
        Ok(str)
    }
}

impl Key {
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_owned()
    }
}

#[derive(Clone, Debug)]
pub struct Value(Vec<u8>);

impl From<String> for Value {
    fn from(value: String) -> Self {
        Value(value.as_bytes().to_vec())
    }
}

impl Value {
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_owned()
    }
}

pub trait KeyIdentifier {
    fn key_name(&self, agent: AgentName) -> Key;
}

pub trait ValueBuilder {
    fn build_value(&self) -> Result<Value, ModelError>
    where
        Self: Serialize,
    {
        let json = serde_json::to_string(self)
            .map_err(|err| ModelError::BuildValueError(err.to_string()))?;

        Ok(Value::from(json))
    }
}

pub trait Model: KeyIdentifier + ValueBuilder
where
    Self: Serialize,
{
    fn build(&self, agent_name: AgentName) -> Result<(Key, Value), ModelError> {
        let key = self.key_name(agent_name);
        let value = self.build_value()?;
        Ok((key, value))
    }
}
