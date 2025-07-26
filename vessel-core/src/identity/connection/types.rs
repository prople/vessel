//! # Vessel Identity Connection Types
//!
//! This module provides secure peer-to-peer connection establishment using ECDH key agreement
//! and W3C DID-based identity management.
//!
//! ## Overview
//!
//! The connection system enables secure communication between vessel agents through:
//! - **ECDH Key Agreement**: Generates shared secrets without transmitting private keys
//! - **DID-based Identity**: Uses W3C Decentralized Identifiers for peer identification
//! - **Secure Key Storage**: Private keys encrypted using KeySecure with user passwords
//! - **State Management**: Complete connection lifecycle from request to establishment
//!
//! ## Quick Start
//!
//! ### Creating a Connection (Sender Side)
//! ```rust
//! use vessel_core::identity::connection::*;
//!
//! // Submit a connection request to a peer
//! let api = ConnectionAPIImpl::new(repo, rpc);
//! api.request_submit("StrongPassword123!@#", "did:example:peer123").await?;
//! ```
//!
//! ### Handling Connection Requests (Receiver Side)
//! ```rust
//! // List pending requests
//! let requests = api.request_list().await?;
//!
//! // Approve a request
//! api.request_response(
//!     connection_id,
//!     Approval::Approve,
//!     Some("MyPassword123!@#".to_string())
//! ).await?;
//! ```
//!
//! ## Connection Lifecycle
//!
//! ```text
//! Sender (Alice)                    Receiver (Bob)
//!      │                                 │
//!      │ 1. request_submit()             │
//!      │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─►│ 2. request_connect()
//!      │                                 │    (via RPC)
//!      │                                 │
//!      │                                 │ 3. request_response(Approve)
//!      │◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │ ─ ─ ─ ─ ─ ─ ─ ─
//!      │ 4. request_approval()           │    (via RPC)
//!      │    (via RPC)                    │
//!      │                                 │
//!      │ 5. Both parties have            │
//!      │    shared secret & can          │
//!      │    communicate securely         │
//! ```
//!
//! ## Security Properties
//!
//! - **Perfect Forward Secrecy**: Each connection uses unique ECDH key pairs
//! - **No Private Key Transmission**: Only public keys are exchanged
//! - **Password-Protected Storage**: Private keys encrypted with KeySecure
//! - **Input Validation**: All data validated before cryptographic operations
//! - **State Isolation**: Connections are independent and don't affect each other
//!
//! ## Type Safety
//!
//! All critical data types use the newtype pattern for compile-time safety:
//! - [`ConnectionID`] - UUID validation
//! - [`PeerDIDURI`] - W3C DID format validation  
//! - [`PeerKey`] - Hex key format validation (64 characters)
//! - [`OwnKey`] - Internal key representation
//! - [`OwnSharedSecret`] - ECDH-derived shared secret
//!
//! ## Error Handling
//!
//! All operations return [`ConnectionError`] with specific error variants:
//! - Validation errors for malformed input
//! - Cryptographic errors for ECDH/KeySecure failures
//! - State errors for invalid connection transitions
//! - Network errors for RPC communication failures
//!
//! ## Examples
//!
//! ### Manual Connection Building
//! ```rust
//! let connection = Connection::builder()
//!     .with_id("550e8400-e29b-41d4-a716-446655440000")
//!     .with_peer_did_uri("did:example:alice123")
//!     .with_peer_key("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
//!     .with_password("StrongPassword123!@#")
//!     .build()?;
//!
//! println!("Shared secret: {}", connection.get_own_shared_secret());
//! ```
//!
//! ### Validation Examples
//! ```rust
//! // Validate before using
//! PeerKey::validate("1234567890abcdef...")?;
//! ConnectionID::validate("550e8400-e29b-41d4-a716-446655440000")?;
//! PeerDIDURI::validate("did:example:peer123")?;
//! ```

use std::fmt::{Debug, Display};

use derive_more::{AsRef, From, Into};
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
    /// UUID format validation failed
    ///
    /// This error occurs when a connection ID doesn't match UUID v4 format.
    ///
    /// # Common Causes
    /// - Empty string: `""`
    /// - Invalid format: `"not-a-uuid"`  
    /// - Wrong length: `"123-456-789"`
    /// - Invalid characters: `"ggge8400-e29b-41d4-a716-446655440000"`
    ///
    /// # Example
    /// ```rust
    /// # use vessel_core::identity::connection::types::*;
    /// let result = ConnectionID::new("invalid-uuid".to_string());
    /// assert!(matches!(result.unwrap_err(), ConnectionError::ValidationError(_)));
    /// ```
    #[error("invalid UUID format: {0}")]
    InvalidUUIDFormat(String),

    #[error("invalid DID URI: {reason}")]
    InvalidDIDURI { reason: String },

    #[error("invalid hex key: expected {expected} chars, got {actual}")]
    InvalidHexKeyLength { expected: usize, actual: usize },

    #[error("hex key contains invalid characters: {invalid_chars}")]
    InvalidHexKeyChars { invalid_chars: String },

    #[error("password too weak: {}", requirements.join(", "))]
    WeakPassword { requirements: Vec<String> },

    // ✅ Specific crypto errors
    #[error("ECDH key agreement failed: {0}")]
    ECDHFailure(String),

    #[error("KeySecure encryption failed: {0}")]
    KeySecureEncryption(String),

    #[error("Blake3 hashing failed: {0}")]
    Blake3Hashing(String),

    // ✅ State transition errors
    #[error("invalid state transition: cannot go from {from} to {to}")]
    InvalidStateTransition { from: State, to: State },

    #[error("unknown error: {0}")]
    UnknownError(String),

    #[error("invalid multiaddr: {0}")]
    InvalidMultiAddr(String),

    #[error("entity error: {0}")]
    EntityError(String),

    #[error("shared secret error: {0}")]
    SharedSecretError(String),

    #[error("json serialization error: {0}")] // ✅ Fixed message
    JSONError(String),

    #[error("json deserialization error: {0}")] // ✅ Fixed message
    JSONUnserializeError(String),

    // ✅ Add missing critical error variants
    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("cryptographic operation failed: {0}")]
    CryptographicError(String),

    #[error("invalid connection id: {0}")]
    InvalidConnectionID(String),

    #[error("invalid peer key: {0}")]
    InvalidPeerKey(String),

    #[error("password validation failed: {0}")]
    InvalidPassword(String),

    #[error("connection not found: {0}")]
    ConnectionNotFound(String),

    #[error("connection already exists: {0}")]
    ConnectionAlreadyExists(String),

    #[error("not implemented")]
    NotImplementedError,
}

// ✅ Enhanced ConnectionContext with future extensibility
/// ConnectionContext is a context for each new connection request
///
/// This enum will be used to identify the context of the connection request
/// it will be used to differentiate between different types of connection requests
/// such as connection, chat, or other types of connection requests
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(crate = "self::serde")]
pub enum ConnectionContext {
    Connection,
    // Future contexts can be added here:
    // Chat,
    // FileTransfer,
    // VideoCall,
}

impl Default for ConnectionContext {
    fn default() -> Self {
        Self::Connection
    }
}

// ✅ Enhanced State with more granular states for connection lifecycle
/// State represent connection's states between two peers
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(crate = "self::serde")]
pub enum State {
    /// Initial state when connection request is created
    Pending,
    /// Waiting for peer response (we initiated the connection request)
    PendingOutgoing,
    /// Received request, waiting for our response (peer initiated the request)
    PendingIncoming,
    /// Connection has been established successfully
    Established,
    /// Connection was rejected by the peer
    Rejected,
    /// Connection was cancelled by the sender
    Cancelled,
    /// Connection has expired or timed out
    Expired,
    /// Connection encountered an error
    Failed,
}

impl Default for State {
    fn default() -> Self {
        Self::Pending
    }
}

impl Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Pending => write!(f, "pending"),
            State::PendingOutgoing => write!(f, "pending_outgoing"),
            State::PendingIncoming => write!(f, "pending_incoming"),
            State::Established => write!(f, "established"),
            State::Rejected => write!(f, "rejected"),
            State::Cancelled => write!(f, "cancelled"),
            State::Expired => write!(f, "expired"),
            State::Failed => write!(f, "failed"),
        }
    }
}

/// Approval represent the approval state of the connection request
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "self::serde")]
pub enum Approval {
    Approve,
    Reject,
}

// ✅ Add Display implementations for all newtype structs
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Newtype, From, Into, AsRef)]
#[serde(crate = "self::serde")]
pub struct ConnectionID(String);

impl Display for ConnectionID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ConnectionID {
    /// Validates connection ID format without creating instance
    pub fn validate(id: &str) -> Result<(), ConnectionError> {
        if id.is_empty() {
            return Err(ConnectionError::ValidationError(
                "Connection ID cannot be empty".to_string(),
            ));
        }

        use rst_common::standard::uuid::Uuid;
        Uuid::parse_str(id)
            .map_err(|_| ConnectionError::ValidationError("Invalid UUID format".to_string()))?;

        Ok(())
    }

    /// Creates a new ConnectionID with validation
    pub fn new(id: String) -> Result<Self, ConnectionError> {
        Self::validate(&id)?;
        Ok(Self(id))
    }

    /// Creates ConnectionID without validation (for internal use)
    pub(crate) fn from_validated(id: String) -> Self {
        Self(id)
    }

    /// Generates a new random ConnectionID
    pub fn generate() -> Self {
        use rst_common::standard::uuid::Uuid;
        Self(Uuid::new_v4().to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Newtype, From, Into, AsRef)]
#[serde(crate = "self::serde")]
pub struct PeerDIDURI(String);

impl Display for PeerDIDURI {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PeerDIDURI {
    /// Validates DID URI format without creating instance
    pub fn validate(uri: &str) -> Result<(), ConnectionError> {
        if !uri.starts_with("did:") {
            return Err(ConnectionError::ValidationError(
                "DID URI must start with 'did:'".to_string(),
            ));
        }

        let parts: Vec<&str> = uri.split(':').collect();
        if parts.len() < 3 {
            return Err(ConnectionError::ValidationError(
                "Invalid DID URI format: insufficient components".to_string(),
            ));
        }

        if parts[1].is_empty() {
            return Err(ConnectionError::ValidationError(
                "Invalid DID URI format: method cannot be empty".to_string(),
            ));
        }

        if parts[2].is_empty() {
            return Err(ConnectionError::ValidationError(
                "Invalid DID URI format: identifier cannot be empty".to_string(),
            ));
        }

        Ok(())
    }

    /// Creates a new PeerDIDURI with validation
    pub fn new(uri: String) -> Result<Self, ConnectionError> {
        Self::validate(&uri)?;
        Ok(Self(uri))
    }

    /// Creates PeerDIDURI without validation (for internal use)  
    pub(crate) fn from_validated(uri: String) -> Self {
        Self(uri)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Newtype, From, Into, AsRef)]
#[serde(crate = "self::serde")]
pub struct PeerKey(String);

impl Display for PeerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PeerKey {
    /// Validates peer key format without creating instance
    pub fn validate(key: &str) -> Result<(), ConnectionError> {
        let key_clean = if key.starts_with("0x") {
            &key[2..]
        } else {
            key
        };

        if key_clean.len() % 2 != 0 {
            return Err(ConnectionError::ValidationError(
                "Invalid peer key: odd number of hex characters".to_string(),
            ));
        }

        if !key_clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ConnectionError::ValidationError(
                "Invalid peer key: contains non-hex characters".to_string(),
            ));
        }

        if key_clean.len() != 64 {
            return Err(ConnectionError::ValidationError(format!(
                "Invalid peer key length: expected 64 hex characters, got {}",
                key_clean.len()
            )));
        }

        Ok(())
    }

    /// Creates new PeerKey with validation
    pub fn new(key: String) -> Result<Self, ConnectionError> {
        Self::validate(&key)?;
        Ok(Self(key))
    }

    /// Creates PeerKey without validation (for internal use)
    pub(crate) fn from_validated(key: String) -> Self {
        Self(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Newtype, From, Into, AsRef)]
#[serde(crate = "self::serde")]
pub struct OwnKey(String);

impl Display for OwnKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Newtype, From, Into, AsRef)]
#[serde(crate = "self::serde")]
pub struct OwnSharedSecret(String);

impl Display for OwnSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ✅ Add password validation utility
/// Password validation utilities
pub struct PasswordValidator;

impl PasswordValidator {
    pub fn validate(password: &str) -> Result<(), ConnectionError> {
        if password.is_empty() {
            return Err(ConnectionError::InvalidPassword(
                "Password cannot be empty".to_string(),
            ));
        }

        if password.len() < 12 {
            // ✅ Increased from 8 to 12
            return Err(ConnectionError::InvalidPassword(
                "Password must be at least 12 characters long".to_string(),
            ));
        }

        // ✅ Add complexity requirements
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        if !has_lowercase || !has_uppercase || !has_digit || !has_special {
            return Err(ConnectionError::InvalidPassword(
                "Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character".to_string()
            ));
        }

        Ok(())
    }
}

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

    /// Handles incoming connection requests from remote peers.
    ///
    /// This method is called when a peer sends a connection request via RPC.
    /// The sender provides their DID URI so the receiver knows who is requesting connection.
    async fn request_connect(
        &self,
        connection_id: ConnectionID,
        sender_did_uri: PeerDIDURI, // ✅ Added: Who is making the request
        receiver_did_uri: PeerDIDURI, // ✅ Added: Who should receive the request
        sender_public_key: PeerKey, // ✅ Renamed for clarity
    ) -> Result<(), ConnectionError>;

    /// Handles connection approval notifications from remote peers.
    async fn request_approval(
        &self,
        connection_id: ConnectionID,
        approver_did_uri: PeerDIDURI, // ✅ Added: Who approved the connection
        approver_public_key: PeerKey, // ✅ Renamed for clarity
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
    /// It will send a connection request to the peer with the given `password`, `peer_did_uri`, and `own_did_uri`.
    /// The `password` is used to generate the [`KeySecure`] object for the own key,
    /// `peer_did_uri` is the DID URI of the target peer, and `own_did_uri` is the DID URI of the sender.
    ///
    /// When this method is called, the sender's vessel should call the [`request_connect`] method to notify the peer
    /// with proper identity context so the receiver knows who is making the request.
    async fn request_submit(
        &self,
        password: String,
        peer_did_uri: PeerDIDURI, // ✅ Changed from String to PeerDIDURI
        own_did_uri: PeerDIDURI,  // ✅ Changed from String to PeerDIDURI
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
    async fn update_state(
        &self,
        connection_id: ConnectionID,
        state: State,
    ) -> Result<(), ConnectionError>;
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
        own_did_uri: PeerDIDURI,  // ✅ Added: Sender's DID URI
        peer_did_uri: PeerDIDURI, // ✅ Added: Receiver's DID URI (for context)
        peer_public_key: PeerKey, // ✅ Renamed: This is sender's public key
    ) -> Result<(), ConnectionError>;

    async fn request_approval(
        &self,
        connection_id: ConnectionID,
        own_did_uri: PeerDIDURI,  // ✅ Added: Approver's DID URI
        peer_public_key: PeerKey, // This is approver's public key
    ) -> Result<(), ConnectionError>;

    async fn request_remove(
        &self,
        connection_id: ConnectionID,
        own_did_uri: PeerDIDURI, // ✅ Added: Requester's DID URI
    ) -> Result<(), ConnectionError>;
}

/// `ConnectionAPIImplBuilder` is a trait behavior that provides
/// base application logic's handlers
pub trait ConnectionAPIImplBuilder<TEntityAccessor>:
    ConnectionAPI<EntityAccessor = TEntityAccessor>
where
    TEntityAccessor: ConnectionEntityAccessor,
{
    type Repo: RepoBuilder<EntityAccessor = TEntityAccessor>;
    type RPCImplementer: RpcBuilder;

    fn repo(&self) -> Self::Repo;
    fn rpc(&self) -> Self::RPCImplementer;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_id_validation() {
        // ✅ Valid UUID
        let valid_id = "550e8400-e29b-41d4-a716-446655440000";
        assert!(ConnectionID::new(valid_id.to_string()).is_ok());

        // ✅ Invalid UUIDs
        let invalid_ids = ["", "not-a-uuid", "123-456-789"];
        for invalid_id in invalid_ids {
            assert!(ConnectionID::new(invalid_id.to_string()).is_err());
        }
    }

    #[test]
    fn test_peer_key_validation() {
        // ✅ Valid key (64 hex characters)
        let valid_key = "1234567890abcdef".repeat(4); // 64 chars
        assert!(PeerKey::new(valid_key).is_ok());

        // ✅ Valid key with 0x prefix
        let key_with_prefix = format!("0x{}", "1234567890abcdef".repeat(4));
        assert!(PeerKey::new(key_with_prefix).is_ok());

        // ✅ Invalid keys
        assert!(PeerKey::new("short".to_string()).is_err()); // Too short
        assert!(PeerKey::new("invalid_hex_chars".to_string()).is_err()); // Non-hex
        assert!(PeerKey::new("123".to_string()).is_err()); // Odd length
    }

    #[test]
    fn test_did_uri_validation() {
        // ✅ Valid DID
        assert!(PeerDIDURI::new("did:example:123456".to_string()).is_ok());

        // ✅ Invalid DIDs
        assert!(PeerDIDURI::new("not-a-did".to_string()).is_err());
        assert!(PeerDIDURI::new("did:".to_string()).is_err());
        assert!(PeerDIDURI::new("did:method".to_string()).is_err());
    }

    #[test]
    fn test_password_validation() {
        // ✅ Valid password
        assert!(PasswordValidator::validate("StrongPassword123!@#").is_ok());

        // ✅ Invalid passwords
        assert!(PasswordValidator::validate("").is_err()); // Empty
        assert!(PasswordValidator::validate("short").is_err()); // Too short
        assert!(PasswordValidator::validate("onlylowercase").is_err()); // Missing requirements
        assert!(PasswordValidator::validate("ONLYUPPERCASE").is_err()); // Missing requirements
        assert!(PasswordValidator::validate("NoNumbers!@#").is_err()); // Missing numbers
        assert!(PasswordValidator::validate("NoSpecialChars123").is_err()); // Missing special chars
    }
}
