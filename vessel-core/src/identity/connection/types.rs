use std::fmt::Debug;

use derive_more::{From, Into};
use the_newtype::Newtype;

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::with_errors::thiserror::{self, Error};

use rstdev_domain::entity::ToJSON;

use prople_crypto::keysecure::KeySecure;

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

    #[error("entity error: {0}")]
    EntityError(String),

    #[error("shared secret error: {0}")]
    SharedSecretError(String),

    #[error("shared secret error: {0}")]
    JSONError(String),

    #[error("shared secret error: {0}")]
    JSONUnserializeError(String),

    #[error("not implemented")]
    NotImplementedError,
}

/// ConnectionContext is a context for each new connection request
///
/// This enum will be used to identify the context of the connection request
/// it will be used to differentiate between different types of connection requests
/// such as connection, chat, or other types of connection requests
///
/// For now, we only have one context which is [`ConnectionContext::Connection`]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "self::serde")]
pub enum ConnectionContext {
    Connection,
}

/// State represent connection's states between two peers
///
/// When the connection request send for the first time, it will always on [`State::Pending`] state
/// Once the peer able to answer the challenge successfully and correct it will update into [`State::Established`]
/// which means the connection between both peers already been established successfully
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "self::serde")]
pub enum State {
    Pending,
    Established,
}

/// Approval represent the approval state of the connection request
///
/// This enum will be used by a peer to approve or reject a connection request from their sides
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "self::serde")]
pub enum Approval {
    Approve,
    Reject,
}

#[derive(Default, From, Into, Newtype)]
pub struct PeerDIDURI(String);

#[derive(Default, From, Into, Newtype)]
pub struct PeerKey(String);

#[derive(Default, From, Into, Newtype)]
pub struct OwnKey(String);

#[derive(Default, From, Into, Newtype)]
pub struct OwnSharedSecret(String);

#[derive(Default, From, Into, Newtype)]
pub struct ConnectionID(String);

/// ConnectionEntityPeer is a trait used to access the peer's properties
pub trait ConnectionEntityPeer {
    fn get_peer_did_uri(&self) -> PeerDIDURI;
    fn get_peer_key(&self) -> PeerKey;
    fn get_peer_connection_id(&self) -> ConnectionID;
}

/// ConnectionEntityOwn is a trait used to access the own's properties
pub trait ConnectionEntityOwn {
    fn get_own_key(&self) -> OwnKey;
    fn get_own_keysecure(&self) -> KeySecure;
    fn get_own_shared_secret(&self) -> OwnSharedSecret;
}

/// `ConnectionEntityAccessor` it's a special trait used to access main Connection entity
/// property fields.
///
/// This entity  will be useful from the outside of this crate
/// to access those fields because we need to protect the properties from direct
/// access or manipulation from outside
///
/// This trait contain `get_own_keysecure` method which will return the `KeySecure` object of the "own key"
/// Each time a connection request is sent, it will generate a new ECDH key pairs, including the private key
/// for the self keys, we need to save the private key in a secure storage which is using [`KeySecure`] object
/// 
/// This trait splitted into two traits, [`ConnectionEntityPeer`] and [`ConnectionEntityOwn`] 
pub trait ConnectionEntityAccessor:
    ConnectionEntityPeer
    + ConnectionEntityOwn
    + Clone
    + Debug
    + ToJSON
    + TryInto<Vec<u8>>
    + TryFrom<Vec<u8>>
{
    fn get_id(&self) -> ConnectionID;
    fn get_state(&self) -> State;
    fn get_context(&self) -> ConnectionContext;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

/// ConnectionAPI is main entrypoint to communicate with the `Connection` domain
#[async_trait]
pub trait ConnectionAPI: Clone {
    type EntityAccessor: ConnectionEntityAccessor;

    /// request_connect is a method to send a connection request to the peer
    ///
    /// It will send a connection request to the peer with the given `peer_did_uri` and `peer_public_key`.
    /// The `peer_did_uri` is the DID URI of the sender's peer, and `peer_public_key` is the public key of the sender's peer.
    /// The `connection_id` is the unique identifier for the connection request.
    async fn request_connect(
        &self,
        connection_id: ConnectionID,
        peer_did_uri: PeerDIDURI,
        peer_public_key: PeerKey,
    ) -> Result<(), ConnectionError>;

    /// request_approval is a method to notify the peer to approve the connection request
    ///
    /// When the sender got this method called, it means the peer already approved the connection request,
    /// and the sender should update their [`ConnectionEntityAccessor`] and `peer_public_key`.
    async fn request_approval(
        &self,
        connection_id: ConnectionID,
        peer_public_key: PeerKey,
    ) -> Result<(), ConnectionError>;

    /// request_response is a method to send the response of the connection request
    ///
    /// This method will send the response of the connection request to the peer only if the peer has already approved the connection request.
    /// If the peer has not approved the connection request, the implementer should remove the connection request
    /// from the repository, without need to notify the peer.
    ///
    /// If the `approval` is [`Approval::Approve`], it also generate a new [`ConnectionEntityAccessor`] object with given
    /// password and save it to the repository.
    ///
    /// When this method called by the peer, their vessel should call the [`request_approval`] method to notify the sender
    async fn request_response(
        &self,
        connection_id: ConnectionID,
        approval: Approval,
        password: Option<String>,
    ) -> Result<(), ConnectionError>;

    /// request_cancel is a method to cancel the connection request
    ///
    /// This method should be used by the sender to their peer to cancel the connection request.
    /// When this method is called, the connection request will be removed from the repository,
    /// and the peer will be notified to remove the connection request as well.
    async fn request_cancel(&self, connection_id: ConnectionID) -> Result<(), ConnectionError>;

    /// request_remove is a method to remove the connection request
    ///
    /// This method should be used by the peer to remove the connection request
    async fn request_remove(&self, connection_id: ConnectionID) -> Result<(), ConnectionError>;

    /// request_submit is a method to submit the connection request
    ///
    /// It will send a connection request to the peer with the given `password` and `peer_did_uri`.
    /// The `password` used to generate the [`KeySecure`] object for the own key,
    /// and `peer_did_uri` is the DID URI of the peer.
    ///
    /// When this method called, the sender's vessel should call the [`request_connect`] method to notify the peer
    async fn request_submit(
        &self,
        password: String,
        peer_did_uri: String,
    ) -> Result<(), ConnectionError>;

    /// request_submissions is a method to get all connection requests that have been submitted
    ///
    /// This method should be used from the sender's sides
    async fn request_submissions(&self) -> Result<Vec<Self::EntityAccessor>, ConnectionError>;

    /// request_list is a method to get all connection requests that have been sent
    ///
    /// This method should be used from the peer's sides
    async fn request_list(&self) -> Result<Vec<Self::EntityAccessor>, ConnectionError>;
}

/// RepoBuilder is a `Connection Repository` abstraction by implementing repository pattern
#[async_trait]
pub trait RepoBuilder: Clone + Sync + Send {
    type EntityAccessor: ConnectionEntityAccessor;

    async fn save(&self, connection: &Self::EntityAccessor) -> Result<(), ConnectionError>;
    async fn update_state(&self, connection_id: ConnectionID, state: State) -> Result<(), ConnectionError>;
    async fn remove(&self, connection_id: ConnectionID) -> Result<(), ConnectionError>;
    async fn get_connection(
        &self,
        connection_id: ConnectionID,
    ) -> Result<Self::EntityAccessor, ConnectionError>;
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
        connection_id: ConnectionID,
        peer_did_uri: PeerDIDURI,
        peer_public_key: PeerKey,
    ) -> Result<(), ConnectionError>;
    
    async fn request_approval(
        &self,
        connection_id: String,
        peer_public_key: PeerKey,
    ) -> Result<(), ConnectionError>;
    
    async fn request_remove(&self, connection_id: ConnectionID) -> Result<(), ConnectionError>;
}

/// `ConnectionAPIImplBuilder` is a trait behavior that provides
/// base application logic's handlers
pub trait ConnectionAPIImplBuilder<TEntityAccessor>: ConnectionAPI<EntityAccessor = TEntityAccessor>
where
    TEntityAccessor: ConnectionEntityAccessor,
{
    type Repo: RepoBuilder<EntityAccessor = TEntityAccessor>;
    type RPCImplementer: RpcBuilder;

    fn repo(&self) -> Self::Repo;
    fn rpc(&self) -> Self::RPCImplementer;
}
