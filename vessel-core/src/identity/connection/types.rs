use std::fmt::Debug;

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::with_errors::thiserror::{self, Error};

use rstdev_domain::entity::ToJSON;

/// ConnectionError is a base error types for the `Connection` domain
///
/// It will contains any possible errors for the `connection`
#[derive(Debug, PartialEq, Error, Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub enum ConnectionError {
    #[error("unknown error: {0}")]
    UnknownError(String),

    #[error("invalid multiaddr: {0}")]
    InvalidMultiAddr(String),
}

/// State represent connection's states between two peers
///
/// When the connection request send for the first time, it will always on [`State::Pending`] state
/// Once the peer able to answer the challenge successfully and correct it will update into [`State::Established`]
/// which means the connection between both peers already been established successfully
pub enum State {
    Pending,
    Established,
}

/// `ConnectionEntityAccessor` it's a special trait used to access main Connection entity
/// property fields.
///
/// This entity  will be useful from the outside of this crate
/// to access those fields because we need to protect the properties from direct
/// access or manipulation from outside
pub trait ConnectionEntityAccessor:
    Clone + Debug + ToJSON + TryInto<Vec<u8>> + TryFrom<Vec<u8>>
{
    fn get_id(&self) -> String;
    fn get_peer_did_uri(&self) -> String;
    fn get_peer_key(&self) -> String;
    fn get_own_did_uri(&self) -> String;
    fn get_own_key(&self) -> String;
    fn get_state(&self) -> State;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

/// ConnectionChallenge used as a response to the peer sender that request to connect
///
/// It will contains two important properties:
///
/// - Connection id
/// - Connection challenge
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct ConnectionChallenge {
    id: String,
    challenge: String,
}

/// ConnectionAPI is main entrypoint to communicate with the `Connection` domain
#[async_trait]
pub trait ConnectionAPI: Clone {
    type EntityAccessor: ConnectionEntityAccessor;

    /// request_connect is an RPC call method used by peers to receive the connection request
    ///
    /// The `own_did_uri` parameter is an URI address in DID format belongs to sender
    /// The `peer_did_uri` parameter is an URI address in DID format belongs to peer
    ///
    /// Each time a peer send a connection request it will generate new ECDH key pairs, and use the public
    /// key as a payload.
    ///
    /// The expected result if success is a connection challenge which contains a connection id and an encrypted
    /// value which is random of string that generated using shared secret key. The sender must be able to decrypt
    /// and re-encrypt it later as response challenge
    async fn request_connect(
        &self,
        own_did_uri: String,
        peer_did_uri: String,
        public_key: String,
    ) -> Result<ConnectionChallenge, ConnectionError>;

    /// response_challenge is an RPC call method used by the sender to send back their public key with a challenge
    ///
    /// An answer parameter actually is an encrypted random text or characters
    /// with the sharedsecret key generated through ECDH algorithm. The ECDH algorithm may generate a shared secret key
    /// without never exchange their private keys
    ///
    /// The expected condition if it's success is our peer must be able to re-encrypt the value using their shared
    /// secret key. Once it's correct it update the connection status to established
    async fn response_challenge(
        &self,
        connection_id: String,
        answer: String,
    ) -> Result<(), ConnectionError>;

    /// submit_request used by the sender to submit the connection request from their client app like from CLI or others
    ///
    /// When an user submit request it must able to generate the ECDH key pairs, and use the public as additional parameter
    /// to the peer through [`ConnectionAPI::request_connect`]
    async fn submit_request(
        &self,
        peer_did_uri: String,
        own_did_uri: String,
    ) -> Result<ConnectionChallenge, ConnectionChallenge>;

    async fn remove_request(&self, id: String) -> Result<(), ConnectionError>;
    async fn get_connection(&self, id: String) -> Result<Self::EntityAccessor, ConnectionError>;
    async fn list_connections(
        &self,
        state: Option<State>,
    ) -> Result<Vec<Self::EntityAccessor>, ConnectionError>;
}

/// RepoBuilder is a `Connection Repository` abstraction by implementing repository pattern
#[async_trait]
pub trait RepoBuilder: Clone + Sync + Send {
    type EntityAccessor: ConnectionEntityAccessor;

    async fn save_request(&self, connection: &Self::EntityAccessor) -> Result<(), ConnectionError>;
    async fn update_state(&self, id: String, state: State) -> Result<(), ConnectionError>;
    async fn remove_request(&self, id: String) -> Result<(), ConnectionError>;
    async fn get_connection(&self, id: String) -> Result<Self::EntityAccessor, ConnectionError>;
    async fn list_connections(
        &self,
        state: Option<State>,
    ) -> Result<Vec<Self::EntityAccessor>, ConnectionError>;
}

/// `RpcBuilder` is a trait behavior used as `JSON-RPC` client builder
/// to calling other `Vessel` agents.
#[async_trait]
pub trait RpcBuilder: Clone {
    async fn request_connect(
        &self,
        own_did_uri: String,
        peer_did_uri: String,
        public_key: String,
    ) -> Result<ConnectionChallenge, ConnectionError>;

    async fn response_challenge(
        &self,
        connection_id: String,
        answer: String,
    ) -> Result<(), ConnectionError>;
}