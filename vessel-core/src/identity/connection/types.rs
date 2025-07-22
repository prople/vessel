use std::fmt::Debug;

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::uuid::Uuid;
use rst_common::with_errors::thiserror::{self, Error};

use rstdev_domain::entity::ToJSON;

use prople_crypto::keysecure::KeySecure;

pub const CONTEXT_CONNECTION_REQUEST: &str = "connection_request";

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

/// State represent connection's states between two peers
///
/// When the connection request send for the first time, it will always on [`State::Pending`] state
/// Once the peer able to answer the challenge successfully and correct it will update into [`State::Established`]
/// which means the connection between both peers already been established successfully
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "self::serde")]
pub enum State {
    Pending,
    Challenged,
    Established,
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
pub trait ConnectionEntityAccessor:
    Clone + Debug + ToJSON + TryInto<Vec<u8>> + TryFrom<Vec<u8>>
{
    fn get_id(&self) -> String;
    fn get_peer_did_uri(&self) -> Option<String>;
    fn get_peer_key(&self) -> Option<String>;
    fn get_own_did_uri(&self) -> String;
    fn get_own_key(&self) -> String;
    fn get_own_keysecure(&self) -> Option<KeySecure>;
    fn get_own_shared_secret(&self) -> Option<String>;
    fn get_state(&self) -> State;
    fn get_proposal(&self) -> Option<ConnectionProposal>;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

/// ConnectionChallenge used as a response to the peer sender that request to connect
///
/// It will contains two important properties:
///
/// - Connection id
/// - Connection challenge
/// - Own public key
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "self::serde")]
pub struct ConnectionChallenge {
    id: String,
    connection_id: String,
    challenge: String,
    public_key: String,
}

/// ConnectionProposal used by a sender as primary request to connect to the peer
///
/// The sender will generate a new ECDH key pairs, and use the public key as a parameter
/// this public key will be used by the peer to generate the shared secret key
///
/// The id is a unique identifier for the connection proposal, it will be used by the peer
/// later to they need to respond the request, either it is accepted or rejected
///
/// The did_uri is the DID URI of the sender, it will be used by the peer to identify the sender
/// and to establish the connection later
///
/// A context is a string that will be used to identify the context of the connection proposal
/// it can be used to provide additional information about the connection proposal
/// such as the purpose of the connection or any other relevant information. A same sender is possible
/// to send multiple connection proposals to the same peer, so the context is useful to differentiate,
/// and only the peer can decide which proposal to accept or reject based on the context
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(crate = "self::serde")]
pub struct ConnectionProposal {
    id: String,
    public_key: String,
    did_uri: String,
    context: String,
}

impl ConnectionProposal {
    pub fn new(public_key: String, did_uri: String, context: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            public_key,
            did_uri,
            context: context.to_string(),
        }
    }

    pub fn get_id(&self) -> &String {
        &self.id
    }

    pub fn get_public_key(&self) -> String {
        self.public_key.to_owned()
    }

    pub fn get_did_uri(&self) -> &String {
        &self.did_uri
    }

    pub fn get_context(&self) -> &String {
        &self.context
    }
}

/// ConnectionAPI is main entrypoint to communicate with the `Connection` domain
#[async_trait]
pub trait ConnectionAPI: Clone {
    type EntityAccessor: ConnectionEntityAccessor;

    /// request_connect is an RPC call method used by peers to receive the connection request
    ///
    /// A peer that receive the connection proposal need to generate a new [`ConnectionEntityAccessor`] object
    /// implementation, and save it to the local storage. The state should be set to [`State::Pending`], and
    /// also without any keysecure, shared secret and the public key generated yet
    async fn request_connect(&self, proposal: ConnectionProposal) -> Result<(), ConnectionError>;

    /// list_proposals is an RPC call method used by the peer to list all new connection proposals
    ///
    /// Each time a peer decide to accept or reject a connection proposal, it should remoeve the proposal
    /// from the list, so that it won't be listed again
    async fn list_requests(&self) -> Result<Vec<Self::EntityAccessor>, ConnectionError>;

    /// response_proposal is an RPC call method used by the peer to respond the connection proposal
    ///
    /// The `accepted` parameter is a boolean value that indicates whether the proposal is accepted or rejected
    /// If the proposal is rejected, the peer should remove the proposal from the list
    ///
    /// When the proposal is accepted, the peer will update the connection state to [`State::Challenged`], and save the
    /// connection challenge into the local storage. The generated challenge should be contains the connection id
    ///
    /// When this method called, the peer vessel node should be able to call the [`request_challenge`] method from the sender
    async fn response_request(
        &self,
        connection_id: String,
        accepted: bool,
    ) -> Result<(), ConnectionError>;

    /// request_challenge is an RPC call method used by the sender to receive a challenge from the peer
    ///
    /// From the sender's perspective, it need to generate a new [`ConnectionEntityAccessor`] object
    /// implementation, and save it to the local storage. The state should be set to [`State::Challenged`], and
    /// also without any keysecure, shared secret and the public key generated yet
    async fn request_challenge(
        &self,
        challenge: ConnectionChallenge,
    ) -> Result<(), ConnectionError>;

    /// list_challenges is an RPC call method used by the sender to list all new challenges
    ///
    /// Each time a sender receive a challenge from the peer, it should save the challenge
    /// to the local storage, so that it can be listed later, and each time a challenge is answered
    /// it should be removed from the list
    async fn list_challenges(&self) -> Result<Vec<ConnectionChallenge>, ConnectionError>;

    /// cancel_request is an RPC call method used by the sender to cancel the connection request
    ///
    /// The `proposal_id` is the unique identifier of the connection proposal. When the sender cancel the request,
    /// it should remove the proposal from the list, and also remove the connection entity from the local storage
    /// If the proposal is not found, it will throw an error
    ///
    /// When the sender call this method, its vessel should be able to call the [`remove_proposal`] method from the peer
    /// to remove the connection entity from the peer's local storage
    async fn cancel_request(&self, proposal_id: String) -> Result<(), ConnectionError>;

    /// answer_challenge is an RPC call method used by the sender to answer the challenge from the peer
    ///
    /// This method used by the peer to check if the answer from the sender is correct or not. If the answer is correct,
    /// the peer will update the connection state to [`State::Established`], if the answer is incorrect,
    /// the peer will remove the connection entity from the local storage and throw an error
    async fn answer_challenge(
        &self,
        connection_id: String,
        answer: String,
    ) -> Result<(), ConnectionError>;

    /// response_challenge is an RPC call method used by the sender to send back their public key with a challenge
    ///
    /// This method is used by the sender to respond the challenge from the peer, the sender should be generate a new
    /// ECDH key pairs, and use the public key as a parameter to generate the shared secret key, and update the connection
    /// entity with the shared secret key and keysecure. The `password` parameter is used to encrypt the keysecure
    ///
    /// An answer parameter actually is an encrypted random text or characters
    /// with the sharedsecret key generated through ECDH algorithm. The ECDH algorithm may generate a shared secret key
    /// without never exchange their private keys
    ///
    /// The expected condition if it's success is our peer must be able to re-encrypt the value using their shared
    /// secret key. Once it's correct it update the connection status to established
    ///
    /// When the sender send the response, it should call the [`answer_challenge`] method from the peer, and waiting for the response
    /// to check if the answer is correct or not. If the answer is correct, the peer will update the connection state to [`State::Established`],
    /// if the answer is incorrect, the peer will remove the connection entity from the local storage and throw an error
    async fn response_challenge(
        &self,
        password: String,
        connection_id: String,
        answer: String,
    ) -> Result<(), ConnectionError>;

    /// submit_request used by the sender to submit the connection request from their client app like from CLI or others
    ///
    /// This method is used by the client application to submit a connection request. At this stage, the *sender* must be
    /// generate their own ECDH key pairs, and use the public key as an additional parameter
    ///
    /// When an user submit request it must able to generate the ECDH key pairs, and use the public as additional parameter
    /// for the [`ConnectionProposal`]. The `ConnectionProposal` will be sent to the peer.
    async fn submit_request(
        &self,
        password: String,
        peer_did_uri: String,
        own_did_uri: String,
    ) -> Result<(), ConnectionError>;

    /// remove_proposal is an RPC call method used by the sender to remove the connection proposal from the peer
    async fn remove_proposal(&self, proposal_id: String) -> Result<(), ConnectionError>;

    async fn get_connection(
        &self,
        connection_id: String,
    ) -> Result<Self::EntityAccessor, ConnectionError>;

    async fn list_connections(
        &self,
        state: Option<State>,
    ) -> Result<Vec<Self::EntityAccessor>, ConnectionError>;
}

/// RepoBuilder is a `Connection Repository` abstraction by implementing repository pattern
#[async_trait]
pub trait RepoConnectionBuilder: Clone + Sync + Send {
    type EntityAccessor: ConnectionEntityAccessor;

    async fn save(
        &self,
        connection: &Self::EntityAccessor,
    ) -> Result<(), ConnectionError>;
    async fn update_state(
        &self,
        id: String,
        state: State,
    ) -> Result<(), ConnectionError>;
    async fn remove(&self, connection_id: String) -> Result<(), ConnectionError>;
    async fn remove_by_proposal(&self, proposal_id: String) -> Result<(), ConnectionError>;
    async fn get_connection(
        &self,
        connection_id: String,
    ) -> Result<Self::EntityAccessor, ConnectionError>;
    async fn list_by_state(
        &self,
        state: Option<State>,
    ) -> Result<Vec<Self::EntityAccessor>, ConnectionError>;
}

#[async_trait]
pub trait RepoChallengeBuilder: Clone + Sync + Send {
    async fn save_challenge(&self, challenge: &ConnectionChallenge) -> Result<(), ConnectionError>;
    async fn remove_challenge(&self, challenge_id: String) -> Result<(), ConnectionError>;
    async fn get_challenge(
        &self,
        challenge_id: String,
    ) -> Result<ConnectionChallenge, ConnectionError>;
    async fn list_challenges(&self) -> Result<Vec<ConnectionChallenge>, ConnectionError>;
}

/// `RpcBuilder` is a trait behavior used as `JSON-RPC` client builder
/// to calling other `Vessel` agents.
#[async_trait]
pub trait RpcBuilder: Clone {
    async fn request_connect(&self, proposal: ConnectionProposal) -> Result<(), ConnectionError>;

    async fn request_challenge(
        &self,
        challenge: ConnectionChallenge,
    ) -> Result<(), ConnectionError>;

    async fn answer_challenge(
        &self,
        connection_id: String,
        answer: String,
    ) -> Result<(), ConnectionError>;

    async fn remove_proposal(&self, proposal_id: String) -> Result<(), ConnectionError>;
}

/// `UsecaseBuilder` is a trait behavior that provides
/// base application logic's handlers
pub trait UsecaseBuilder<TEntityAccessor>: ConnectionAPI<EntityAccessor = TEntityAccessor>
where
    TEntityAccessor: ConnectionEntityAccessor,
{
    type RepoConnectionImplementer: RepoConnectionBuilder<EntityAccessor = TEntityAccessor>;
    type RepoChallengeImplementer: RepoChallengeBuilder;
    type RPCImplementer: RpcBuilder;

    fn repo_connection(&self) -> Self::RepoConnectionImplementer;
    fn repo_challenge(&self) -> Self::RepoChallengeImplementer;
    fn rpc(&self) -> Self::RPCImplementer;
}
