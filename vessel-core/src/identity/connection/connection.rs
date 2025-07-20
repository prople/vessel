use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_crypto::ecdh::keypair::KeyPair;
use prople_crypto::keysecure::types::Password;
use prople_crypto::keysecure::types::ToKeySecure;
use prople_crypto::keysecure::KeySecure;
use prople_crypto::types::{ByteHex, Hexer};

use super::types::{ConnectionEntityAccessor, ConnectionError, State, ConnectionProposal};

/// Connection is a struct that represents a connection between two peers
/// It contains the necessary information to establish a connection, such as the peer's DID URI,
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "self::serde")]
pub struct Connection {
    id: String,
    peer_did_uri: String,
    peer_key: String,
    own_did_uri: String,
    own_key: String,
    own_keysecure: Option<KeySecure>,
    own_shared_secret: Option<String>,
    state: State,
    challenge: String,
    propopsal: ConnectionProposal,

    #[serde(with = "ts_seconds")]
    created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    updated_at: DateTime<Utc>,
}

impl Connection {
    /// Generates a new Connection instance with the provided parameters.
    /// It should generate the ECDH keypair for the own entity and derive the shared secret with the peer's public key.
    /// The generated shared secret will in hashed binary format using the blake3 hashing algorithm.
    ///
    /// # Arguments
    /// * `password` - The password used to build the keysecure from generated keypairs.
    /// * `peer_did_uri` - The DID URI of the peer.
    /// * `peer_key` - The public key of the peer.
    /// * `own_did_uri` - The DID URI of the own entity.
    pub fn generate(
        password: String,
        peer_did_uri: String,
        peer_key: String,
        own_did_uri: String,
        challenge: String,
        proposal: ConnectionProposal,
    ) -> Result<Self, ConnectionError> {
        let own_keypairs = KeyPair::generate();
        let own_keysecure = own_keypairs
            .to_keysecure(Password::from(password))
            .map_err(|err| ConnectionError::EntityError(err.to_string()))?;

        let own_shared_secret = own_keypairs
            .clone()
            .secret(ByteHex::from(peer_key.clone()))
            .to_blake3()
            .map_err(|err| ConnectionError::SharedSecretError(err.to_string()))?
            .hex();

        let out = Self {
            id: Uuid::new_v4().to_string(),
            peer_did_uri,
            peer_key,
            own_did_uri,
            own_key: own_keypairs.pub_key().to_hex().hex(),
            own_keysecure: Some(own_keysecure), 
            own_shared_secret: Some(own_shared_secret),
            challenge,
            state: State::Pending,
            propopsal: proposal,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        Ok(out)
    }

    pub fn update_state(&mut self, state: State) {
        self.state = state;
        self.updated_at = Utc::now();
    }
}

impl ToJSON for Connection {
    fn to_json(&self) -> Result<String, BaseError> {
        serde_json::to_string(self).map_err(|err| BaseError::ToJSONError(err.to_string()))
    }
}

impl TryInto<Vec<u8>> for Connection {
    type Error = ConnectionError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let json =
            serde_json::to_vec(&self).map_err(|err| ConnectionError::JSONError(err.to_string()))?;
        Ok(json)
    }
}

impl TryFrom<Vec<u8>> for Connection {
    type Error = ConnectionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let account: Connection = serde_json::from_slice(&value)
            .map_err(|err| ConnectionError::JSONUnserializeError(err.to_string()))?;
        Ok(account)
    }
}

impl ConnectionEntityAccessor for Connection {
    fn get_id(&self) -> String {
        self.id.to_owned()
    }

    fn get_peer_did_uri(&self) -> String {
        self.peer_did_uri.to_owned()
    }

    fn get_peer_key(&self) -> String {
        self.peer_key.to_owned()
    }

    fn get_own_did_uri(&self) -> String {
        self.own_did_uri.to_owned()
    }

    fn get_own_key(&self) -> String {
        self.own_key.to_owned()
    }

    fn get_own_keysecure(&self) -> Option<KeySecure> {
        self.own_keysecure.to_owned()
    }

    fn get_own_shared_secret(&self) -> Option<String> {
        self.own_shared_secret.to_owned()
    }

    fn get_state(&self) -> State {
        self.state.to_owned()
    }

    fn get_proposal(&self) -> ConnectionProposal {
        self.propopsal.to_owned()
    }

    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    fn get_updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

mod tests {
    use super::*;

    use multiaddr::Multiaddr;

    use prople_did_core::did::query::Params;
    use prople_did_core::did::DID;

    #[allow(dead_code)]
    fn generate_peer() -> (String, String, KeyPair) {
        let peer_did = DID::new();
        let peer_did_uri = peer_did
            .build_uri(Some(Params {
                address: Some(Multiaddr::empty().to_string()),
                hl: None,
            }))
            .unwrap();

        let peer_keypair = KeyPair::generate();
        let peer_key = peer_keypair.pub_key().to_hex().hex();
        (peer_did_uri, peer_key, peer_keypair)
    }

    #[allow(dead_code)]
    fn generate_peer_secret(peer_keypair: KeyPair, receiver_public: String) -> String {
        peer_keypair
            .secret(ByteHex::from(receiver_public))
            .to_blake3()
            .unwrap()
            .hex()
    }

    #[allow(dead_code)]
    fn generate_own() -> (String, String) {
        let own_did = DID::new();
        let own_did_uri = own_did
            .build_uri(Some(Params {
                address: Some(Multiaddr::empty().to_string()),
                hl: None,
            }))
            .unwrap();

        let own_keypair = KeyPair::generate();
        let own_key = own_keypair.pub_key().to_hex().hex();

        (own_did_uri, own_key)
    }

    #[test]
    fn test_success() {
        let (peer_uri, peer_key, peer_keypair) = generate_peer();
        let (own_uri, _) = generate_own();
        let connection = Connection::generate("testing".to_string(), peer_uri, peer_key, own_uri, "challenge".to_string(), ConnectionProposal::default());

        assert!(connection.is_ok());
        assert_eq!(connection.clone().unwrap().state, State::Pending);

        let peer_secret =
            generate_peer_secret(peer_keypair, connection.clone().unwrap().get_own_key());
        assert_eq!(connection.unwrap().own_shared_secret.unwrap(), peer_secret);
    }

    #[test]
    fn test_update_state() {
        let (peer_uri, peer_key, _) = generate_peer();
        let (own_uri, _) = generate_own();
        let mut connection =
            Connection::generate("testing".to_string(), peer_uri, peer_key, own_uri, "challenge".to_string(), ConnectionProposal::default()).unwrap();

        assert_eq!(connection.state, State::Pending);

        connection.update_state(State::Established);
        assert_eq!(connection.state, State::Established);
    }
}
