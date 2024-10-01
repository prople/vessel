use rst_common::standard::serde::{self, Serialize, Deserialize};
use rst_common::standard::serde_json;

use crate::models::types::{AgentName, Key, KeyIdentifier, Model, ModelError, Value, ValueBuilder};

use super::account::Account;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct Accounts(Vec<Account>);

impl Default for Accounts {
    fn default() -> Self {
        Accounts(Vec::new())
    }
}

impl TryFrom<Vec<u8>> for Accounts {
    type Error = ModelError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {     
        let jsonstr = String::from_utf8(value)
            .map_err(|err| ModelError::DeserializeError(err.to_string()))?;

        let deserialized = serde_json::from_str::<Accounts>(&jsonstr)
            .map_err(|err| ModelError::DeserializeError(err.to_string()))?;

        Ok(deserialized)
    }
}

impl Accounts {
    pub fn add(&mut self, account: Account) -> &mut Self {
        self.0.push(account);
        self
    }

    pub fn list(&self) -> Vec<Account> {
        self.0.to_owned()
    }
}

impl KeyIdentifier for Accounts {
    fn key_name(&self, agent: AgentName) -> Key {
        let key = format!("{}_accounts", agent.to_string());
        Key::from(key)
    }
}

impl ValueBuilder for Accounts {
    fn build_value(&self) -> Result<Value, ModelError> {
        let json = serde_json::to_value(self.list())
            .map_err(|err| ModelError::BuildValueError(err.to_string()))?;

        Ok(Value::from(json.to_string()))
    }
}

impl Model for Accounts {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accounts_add_list() {
        let mut accounts = Accounts::default();
        assert_eq!(accounts.list().len(), 0);

        let account1 = Account::default();
        let account2 = Account::default();
        accounts.add(account1).add(account2);
        assert_eq!(accounts.list().len(), 2);
    }

    #[test]
    fn test_key() {
        let accounts = Accounts::default();
        let key = accounts.key_name(AgentName::from("agent_test"));
        let try_key_str = String::from_utf8(key.to_vec());

        assert!(!try_key_str.is_err());
        assert_eq!("agent_test_accounts", try_key_str.unwrap())
    }

    #[test]
    fn test_value() {
        let accounts = Accounts::default();
        let try_value = accounts.build_value();
        assert!(!try_value.is_err());
        
        let value = try_value.unwrap();
        let try_reaccounts = Accounts::try_from(value.to_vec());
        assert!(!try_reaccounts.is_err());
        
        let reaccounts = try_reaccounts.unwrap();
        let revalue = reaccounts.build_value().unwrap();
        assert_eq!(revalue.to_bytes(), value.to_bytes())
    }

    #[test]
    fn test_model() {
        let accounts = Accounts::default();
        let try_model = accounts.build(AgentName::from("agent_test"));
        assert!(!try_model.is_err());

        let (key, value) = try_model.unwrap();
        
        let try_key_str = String::from_utf8(key.to_vec());
        assert!(!try_key_str.is_err());
        assert_eq!("agent_test_accounts", try_key_str.unwrap());
        
        let try_reaccounts = Accounts::try_from(value.to_vec());
        assert!(!try_reaccounts.is_err());
        
        let reaccounts = try_reaccounts.unwrap();
        let revalue = reaccounts.build_value().unwrap();
        assert_eq!(revalue.to_bytes(), value.to_bytes())
    }
}