use rst_common::with_errors::thiserror::{self, Error};

#[derive(Clone, Debug, Error)]
pub enum ModelError {
    #[error("error value: {0}")]
    BuildValueError(String),

    #[error("error deserialize: {0}")]
    DeserializeError(String),
}

#[derive(Clone, Debug)]
pub struct AgentName(String);

impl From<&str> for AgentName {
    fn from(value: &str) -> Self {
        AgentName(String::from(value))
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
    fn build_value(&self) -> Result<Value, ModelError>;
}

pub trait Model: KeyIdentifier + ValueBuilder {
    fn build(&self, agent_name: AgentName) -> Result<(Key, Value), ModelError> {
        let key = self.key_name(agent_name);
        let value = self.build_value()?;
        Ok((key, value))
    }
}
