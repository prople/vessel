use rst_common::standard::serde::{self, Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct DID(String);

impl DID {
    pub fn set(&self, value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for DID {
    fn from(value: &str) -> Self {
        DID(String::from(value))
    }
}

impl ToString for DID {
    fn to_string(&self) -> String {
        self.0.to_owned()
    }
}

impl Default for DID {
    fn default() -> Self {
        DID(String::from(""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        let did = DID::from("did:prople:test");
        assert_eq!(did.to_string(), "did:prople:test")
    }

    #[test]
    fn test_default() {
        let mut did = DID::default();
        assert!(did.to_string().is_empty());

        did = did.set(String::from("did:prople:testing"));
        assert_eq!(did.to_string(), "did:prople:testing")
    }
}
