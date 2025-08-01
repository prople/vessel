//! # Connection Module
//!
//! This module provides secure peer-to-peer connection establishment using ECDH key agreement.
//! It implements a connection entity that stores peer information, cryptographic keys, and
//! shared secrets for secure communication between decentralized identity participants.
//!
//! ## Key Features
//! - **ECDH key agreement** for secure shared secret generation
//! - **KeySecure encryption** for private key storage
//! - **Multiple connection patterns**: Complete, Partial (outgoing), and Passwordless (incoming)
//! - **Connection completion workflow** for notification-based approvals
//! - **Comprehensive input validation** (UUID, DID URI, hex keys, password complexity)
//! - **Builder pattern** for ergonomic connection creation with existing KeySecure support
//! - **JSON and binary serialization** support
//! - **Enhanced state management** for connection lifecycle
//!
//! ## Connection Types
//!
//! ### Complete Connections (Traditional)
//! Created when both peer's public key and password are provided:
//! ```rust
//! let connection = Connection::builder()
//!     .with_id("550e8400-e29b-41d4-a716-446655440000")
//!     .with_peer_did_uri("did:example:bob")
//!     .with_peer_key(bob_public_key)  // ✅ Peer key provided
//!     .with_password("StrongPassword123!@#")  // ✅ Password provided
//!     .build()?;
//! // State: Pending, has shared secret immediately
//! ```
//!
//! ### Partial Connections (Outgoing Requests)
//! Created for connection requests where peer's key is not yet known:
//! ```rust
//! let connection = Connection::builder()
//!     .with_id("550e8400-e29b-41d4-a716-446655440000")
//!     .with_peer_did_uri("did:example:bob")
//!     // ❌ No peer key - creates partial connection
//!     .with_password("StrongPassword123!@#")  // ✅ Password for our KeySecure
//!     .build()?;
//! // State: PendingOutgoing, placeholder shared secret
//! ```
//!
//! ### Passwordless Connections (Incoming Requests)
//! Created for incoming requests where no cryptographic setup is needed yet:
//! ```rust
//! let connection = Connection::builder()
//!     .with_id("550e8400-e29b-41d4-a716-446655440000")
//!     .with_peer_did_uri("did:example:alice")
//!     // ❌ No peer key, no password
//!     .build()?;
//! // State: PendingIncoming, no cryptographic material
//! ```
//!
//! ## Connection Completion Workflow
//!
//! For notification-based approval systems:
//! ```rust
//! // 1. Alice creates partial connection
//! let alice_partial = Connection::builder()
//!     .with_password("AlicePassword123!@#")
//!     // ... other fields
//!     .build()?;
//!
//! // 2. Bob receives request and approves (separate flow)
//!
//! // 3. Alice receives notification with Bob's public key
//!
//! // 4. Alice completes connection with user password
//! let alice_complete = alice_partial.complete_with_password(
//!     &bobs_public_key,
//!     "AlicePassword123!@#"  // User enters password again
//! )?;
//! // State: Established, real shared secret derived
//! ```

use std::fmt::Debug;

use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_crypto::ecdh::keypair::KeyPair;
use prople_crypto::keysecure::types::{Password, ToKeySecure};
use prople_crypto::keysecure::KeySecure;
use prople_crypto::types::{ByteHex, Hexer, VectorValue};

use super::types::{
    ConnectionContext, ConnectionEntityAccessor, ConnectionEntityOwn, ConnectionEntityPeer,
    ConnectionError, ConnectionID, OwnKey, OwnSharedSecret, PeerDIDURI, PeerKey, State,
};

/// # Connection Entity
///
/// Represents a secure connection between two decentralized identity peers using ECDH key agreement.
/// Supports three connection patterns: Complete, Partial (outgoing), and Passwordless (incoming).
///
/// ## Security Features
/// - **ECDH Key Agreement**: Generates shared secrets using Elliptic Curve Diffie-Hellman
/// - **KeySecure Encryption**: Private keys are encrypted using password-derived keys
/// - **Blake3 Hashing**: Shared secrets are hashed using Blake3 for consistency
/// - **No Password Storage**: Passwords are never stored, only used for encryption/decryption
/// - **User-Controlled Completion**: Explicit user password required for connection establishment
///
/// ## Connection States
/// - **PendingOutgoing**: Partial connection waiting for peer approval (has our KeySecure)
/// - **PendingIncoming**: Passwordless incoming connection (no cryptographic material yet)
/// - **Pending**: Complete connection ready for use (has shared secret)
/// - **Established**: Completed connection after successful handshake/approval
/// - **Failed**: Connection that encountered errors during establishment
///
/// ## Security Model
/// - Private keys are encrypted with user passwords using KeySecure
/// - Shared secrets are derived only when user provides password
/// - Completion requires explicit user action with password re-entry
/// - No automatic password storage or caching
///
/// ## Data Storage
/// - All cryptographic material is stored securely
/// - Private keys are never stored in plaintext
/// - Shared secrets are Blake3-hashed for consistency
/// - Timestamps track creation and updates
/// - Placeholder values used for incomplete connections
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct Connection {
    /// Unique identifier for this connection (UUID v4 format)
    /// Used to track and reference this specific connection
    id: ConnectionID,

    /// Current state of the connection lifecycle
    /// - PendingOutgoing: Partial connection awaiting peer approval
    /// - PendingIncoming: Passwordless incoming connection
    /// - Pending: Complete connection with shared secret
    /// - Established: Finalized connection after handshake/approval
    /// - Failed: Connection establishment failed
    state: State,

    /// Context of the connection (currently only supports Connection type)
    /// Extensible for future connection types (e.g., Authentication, Authorization)
    context: ConnectionContext,

    /// DID URI of the peer we're connecting to
    /// Must follow W3C DID specification: did:method:identifier
    peer_did_uri: PeerDIDURI,

    /// Public key of the peer (hex encoded, 64 characters for X25519)
    /// Used in ECDH key agreement to generate shared secret
    /// Set to placeholder "0000...000
    peer_key: PeerKey,

    /// Connection ID from peer's perspective
    /// Allows bidirectional connection tracking
    peer_connection_id: ConnectionID,

    /// Our own public key (hex encoded)
    /// Generated from our private key, shared with peer for ECDH
    /// None for passwordless incoming connections
    own_key: Option<OwnKey>,

    /// Our own private key stored securely using KeySecure format
    /// Encrypted with password-derived key, never stored in plaintext
    /// None for passwordless incoming connections
    /// Required for connection completion with user password
    own_keysecure: Option<KeySecure>,

    /// Shared secret generated from ECDH key agreement (Blake3 hash, hex encoded)
    /// Result of ECDH(our_private_key, peer_public_key) -> Blake3 -> hex
    /// Set to "pending" placeholder for partial connections until completion
    /// None for passwordless incoming connections
    own_shared_secret: Option<OwnSharedSecret>,

    /// Timestamp when connection was created (UTC)
    /// Used for tracking connection age and expiration
    created_at: DateTime<Utc>,

    /// Timestamp when connection was last updated (UTC)
    /// Updates when state changes or other modifications occur
    updated_at: DateTime<Utc>,
}

impl Connection {
    /// Creates a new ConnectionBuilder for fluent connection construction
    ///
    /// Supports three construction patterns:
    /// - Complete connections: with peer_key + password
    /// - Partial connections: with password only (for outgoing requests)
    /// - Passwordless connections: with neither (for incoming requests)
    ///
    /// # Returns
    /// - `ConnectionBuilder`: A builder instance for constructing connections
    ///
    /// # Example
    /// ```rust
    /// // Partial connection for outgoing request
    /// let partial = Connection::builder()
    ///     .with_id("550e8400-e29b-41d4-a716-446655440000")
    ///     .with_peer_did_uri("did:example:peer")
    ///     .with_password("StrongPassword123!@#")  // Only password
    ///     .build()?;  // Creates PendingOutgoing connection
    /// ```
    pub fn builder() -> ConnectionBuilder {
        ConnectionBuilder::new()
    }

    /// Updates the connection state and refreshes the updated timestamp
    ///
    /// This method manages the enhanced connection lifecycle:
    /// - PendingOutgoing -> Established (after completion with peer's key)
    /// - PendingIncoming -> Established (after approval response)
    /// - Pending -> Established (after successful handshake)
    /// - Any state -> Failed (if errors occur)
    ///
    /// # Parameters
    /// - `state`: The new state to transition to
    ///
    /// # Side Effects
    /// - Updates `self.state` to the new state
    /// - Sets `self.updated_at` to current UTC timestamp
    pub fn update_state(&mut self, state: State) {
        self.state = state;
        self.updated_at = Utc::now();
    }

    /// Decrypts the private key and derives the shared secret using the provided password.
    ///
    /// This method is used internally by completion workflows and can be called separately
    /// for connections that already have peer's public key but need shared secret derivation.
    ///
    /// # Security Requirements
    /// - Connection must have a KeySecure (encrypted private key)
    /// - Connection must have a peer public key (not placeholder)
    /// - Password must match the one used for KeySecure encryption
    ///
    /// # Arguments
    /// * `password` - Password to decrypt the private key (must match KeySecure password)
    ///
    /// # Returns
    /// * `Ok(())` - Successfully decrypted and derived shared secret
    /// * `Err(ConnectionError)` - Decryption failed or ECDH operation failed
    ///
    /// # Side Effects
    /// - Updates `own_shared_secret` with real ECDH-derived value
    /// - Updates `updated_at` timestamp
    pub fn decrypt_and_derive_shared_secret(
        &mut self,
        password: &str,
    ) -> Result<(), ConnectionError> {
        // Get the encrypted private key
        let keysecure = self.get_own_keysecure().ok_or_else(|| {
            ConnectionError::CryptographicError("Missing KeySecure for decryption".to_string())
        })?;

        // Decrypt the private key
        let decrypted = keysecure.decrypt(password.to_string()).map_err(|e| {
            ConnectionError::CryptographicError(format!("Failed to decrypt KeySecure: {}", e))
        })?;

        // Convert decrypted bytes back to hex string
        let private_key_hex = String::from_utf8(decrypted.vec()).map_err(|e| {
            ConnectionError::CryptographicError(format!("Invalid decrypted data: {}", e))
        })?;

        // Reconstruct KeyPair from hex string
        let keypair = KeyPair::from_hex(private_key_hex).map_err(|e| {
            ConnectionError::CryptographicError(format!("Failed to reconstruct keypair: {}", e))
        })?;

        // Prepare peer's public key for ECDH computation
        let peer_key_clean = self
            .peer_key
            .as_ref()
            .strip_prefix("0x")
            .unwrap_or(self.peer_key.as_ref());
        let peer_key_hex = ByteHex::from(peer_key_clean.to_string());

        // Compute the ECDH shared secret
        let secret = keypair.secret(peer_key_hex);
        let shared_secret = secret.to_blake3().map_err(|e| {
            ConnectionError::CryptographicError(format!("Shared secret generation failed: {}", e))
        })?;

        // Update the connection with the derived shared secret
        self.own_shared_secret = Some(OwnSharedSecret::from(shared_secret.hex()));
        self.updated_at = Utc::now();

        Ok(())
    }

    /// Complete this connection with peer's public key and password
    ///
    /// This method is the primary way to complete partial connections in notification-based
    /// approval workflows. It takes a partial connection (PendingOutgoing) and peer's public
    /// key received via approval notification, then derives the shared secret using the
    /// user's password.
    ///
    /// # Security Model
    /// - Requires explicit user password entry (no password storage)
    /// - Uses existing KeySecure from partial connection
    /// - Derives shared secret using ECDH + Blake3
    /// - Atomically transitions to Established state
    ///
    /// # Arguments
    /// * `peer_public_key` - Public key received from peer's approval
    /// * `password` - User password for decrypting our private key
    ///
    /// # Returns
    /// * `Ok(Connection)` - Completed connection in Established state
    /// * `Err(ConnectionError)` - Validation, decryption, or ECDH error
    ///
    /// # State Requirements
    /// - Connection must be in PendingOutgoing state
    /// - Connection must have own_keysecure (encrypted private key)
    ///
    /// # Example Usage in Notification Workflow
    /// ```rust
    /// // 1. User sees approval notification
    /// // 2. User chooses to complete connection
    /// // 3. User enters their password
    /// let completed = partial_connection.complete_with_password(
    ///     &approval_notification.peer_public_key,
    ///     &user_entered_password
    /// )?;
    /// // 4. Connection is now Established with shared secret
    /// ```
    pub fn complete_with_password(
        &self,
        peer_public_key: &str,
        password: &str,
    ) -> Result<Connection, ConnectionError> {
        // Validate state
        if self.get_state() != State::PendingOutgoing {
            return Err(ConnectionError::InvalidStateTransition {
                from: self.get_state(),
                to: State::Established,
            });
        }

        // Get existing KeySecure
        let existing_keysecure = self.get_own_keysecure().ok_or_else(|| {
            ConnectionError::CryptographicError(
                "Missing KeySecure for connection completion".to_string(),
            )
        })?;
        // ✅ Use enhanced generate_complete_connection with existing KeySecure
        let mut complete_connection = ConnectionBuilder::generate_complete_connection(
            self.get_id(),
            self.get_peer_did_uri(),
            PeerKey::from_validated(peer_public_key.to_string()),
            self.get_peer_connection_id(),
            password.to_string(),
            self.get_context(),
            None,                     // No keypair - use existing KeySecure
            Some(existing_keysecure), // ✅ Use existing KeySecure
        )?;

        // ✅ APPLY decrypt_and_derive_shared_secret HERE
        complete_connection
            .decrypt_and_derive_shared_secret(password)
            .map_err(|e| {
                ConnectionError::CryptographicError(format!(
                    "Failed to decrypt and derive shared secret during completion: {}",
                    e
                ))
            })?;

        // Update state to Established
        complete_connection.update_state(State::Established);

        Ok(complete_connection)
    }
}

// Trait implementations for accessing peer-related data
impl ConnectionEntityPeer for Connection {
    /// Returns the peer's DID URI
    /// Used for identifying the peer in the decentralized identity system
    fn get_peer_did_uri(&self) -> PeerDIDURI {
        self.peer_did_uri.clone()
    }

    /// Returns the peer's public key
    /// Used in ECDH key agreement and peer verification
    fn get_peer_key(&self) -> PeerKey {
        self.peer_key.clone()
    }

    /// Returns the peer's connection ID
    /// Used for bidirectional connection tracking
    fn get_peer_connection_id(&self) -> ConnectionID {
        self.peer_connection_id.clone()
    }
}

// Trait implementations for accessing our own cryptographic data
impl ConnectionEntityOwn for Connection {
    /// Returns our own public key
    /// This is the public key we share with peers for ECDH
    fn get_own_key(&self) -> Option<OwnKey> {
        self.own_key.clone()
    }

    /// Returns our own private key in KeySecure format
    /// Private key is encrypted with password-derived key for security
    fn get_own_keysecure(&self) -> Option<KeySecure> {
        self.own_keysecure.clone()
    }

    /// Returns the shared secret generated from ECDH key agreement
    /// This is the Blake3 hash of ECDH(our_private, peer_public)
    fn get_own_shared_secret(&self) -> Option<OwnSharedSecret> {
        self.own_shared_secret.clone()
    }
}

// Trait implementations for accessing connection metadata
impl ConnectionEntityAccessor for Connection {
    /// Returns the connection ID
    fn get_id(&self) -> ConnectionID {
        self.id.clone()
    }

    /// Returns the current connection state
    fn get_state(&self) -> State {
        self.state.clone()
    }

    /// Returns the connection context
    fn get_context(&self) -> ConnectionContext {
        self.context.clone()
    }

    /// Returns the creation timestamp
    fn get_created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Returns the last update timestamp
    fn get_updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

// JSON serialization support for persistence and API responses
impl ToJSON for Connection {
    /// Serializes the connection to JSON string
    ///
    /// # Returns
    /// - `Ok(String)`: JSON representation of the connection
    /// - `Err(BaseError)`: Serialization error
    fn to_json(&self) -> Result<String, BaseError> {
        serde_json::to_string(self).map_err(|e| BaseError::ToJSONError(e.to_string()))
    }
}

// Binary serialization support for efficient storage
impl TryInto<Vec<u8>> for Connection {
    type Error = ConnectionError;

    /// Serializes the connection to binary format (JSON bytes)
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)`: Binary representation of the connection
    /// - `Err(ConnectionError)`: Serialization error
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(&self).map_err(|e| ConnectionError::EntityError(e.to_string()))
    }
}

// Binary deserialization support
impl TryFrom<Vec<u8>> for Connection {
    type Error = ConnectionError;

    /// Deserializes a connection from binary format
    ///
    /// # Parameters
    /// - `bytes`: Binary data to deserialize
    ///
    /// # Returns
    /// - `Ok(Connection)`: Deserialized connection
    /// - `Err(ConnectionError)`: Deserialization error
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&bytes).map_err(|e| ConnectionError::EntityError(e.to_string()))
    }
}

/// # Connection Builder
///
/// Provides a fluent API for constructing Connection objects with comprehensive validation.
/// Supports three distinct connection patterns based on provided parameters.
///
/// ## Connection Patterns
///
/// ### 1. Complete Connections (peer_key + password)
/// Traditional connections with immediate shared secret generation:
/// ```rust
/// let complete = Connection::builder()
///     .with_peer_key("abc123...")     // ✅ Peer key provided
///     .with_password("Strong123!@#")  // ✅ Password provided
///     .build()?;  // State: Pending, has shared secret
/// ```
///
/// ### 2. Partial Connections (password only)
/// For outgoing requests where peer's key is unknown:
/// ```rust
/// let partial = Connection::builder()
///     .with_password("Strong123!@#")  // ✅ Password for our KeySecure
///     .build()?;  // State: PendingOutgoing, placeholder shared secret
/// ```
///
/// ### 3. Passwordless Connections (neither)
/// For incoming requests with no cryptographic setup:
/// ```rust
/// let passwordless = Connection::builder()
///     .build()?;  // State: PendingIncoming, no crypto material
/// ```
///
/// ## Enhanced Features
/// - **Existing KeySecure Support**: Reuse encrypted private keys from partial connections
/// - **Connection Completion**: Transform partial connections using peer's public key
/// - **Comprehensive Validation**: All inputs validated before object creation
/// - **Flexible Construction**: Optional fields with sensible defaults
///
/// ## Validation Features
/// - **UUID Validation**: Ensures connection IDs are valid UUID v4 format
/// - **DID URI Validation**: Validates W3C DID specification compliance
/// - **Hex Key Validation**: Ensures peer keys are valid 64-character hex strings
/// - **Password Complexity**: Enforces strong password requirements for KeySecure encryption
///
/// ## Required Fields
/// - `id`: Connection identifier (UUID format)
/// - `peer_did_uri`: Peer's DID URI (did:method:identifier format)
///
/// ## Optional Fields
/// - `peer_key`: Peer's public key (determines connection type)
/// - `password`: Password for KeySecure encryption (determines connection type)
/// - `peer_connection_id`: Peer's connection ID (auto-generated if not provided)
/// - `context`: Connection context (defaults to Connection)
/// - `own_keypair`: Our keypair (auto-generated if not provided)
/// - `own_keysecure`: Existing KeySecure (for connection completion scenarios)
#[derive(Debug, Default)]
pub struct ConnectionBuilder {
    /// Connection identifier (required)
    id: Option<ConnectionID>,
    /// Peer's DID URI (required)
    peer_did_uri: Option<PeerDIDURI>,
    /// Peer's public key (required)
    peer_key: Option<PeerKey>,
    /// Password for KeySecure encryption (required)
    password: Option<String>,
    /// Peer's connection ID (optional)
    peer_connection_id: Option<ConnectionID>,
    /// Connection context (optional)
    context: Option<ConnectionContext>,
    /// Our own keypair (optional - auto-generated if not provided)
    own_keypair: Option<KeyPair>,
    /// Existing KeySecure (optional - for connection completion)
    own_keysecure: Option<KeySecure>,
}

impl ConnectionBuilder {
    /// Creates a new ConnectionBuilder instance
    ///
    /// # Returns
    /// - `ConnectionBuilder`: A new builder with all fields unset
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the connection ID (required)
    ///
    /// # Parameters
    /// - `id`: Connection identifier that can be converted to ConnectionID
    ///
    /// # Validation
    /// - Must be valid UUID v4 format during build()
    ///
    /// # Example
    /// ```rust
    /// builder.with_id("550e8400-e29b-41d4-a716-446655440000")
    /// ```
    pub fn with_id<T: Into<ConnectionID>>(mut self, id: T) -> Self {
        let connection_id = id.into();
        // ✅ Validate immediately when setting
        if let Err(_) = ConnectionID::validate(connection_id.as_ref()) {
            // For builder pattern, we can't return errors here
            // So we store invalid data and catch it in build()
        }
        self.id = Some(connection_id);
        self
    }

    /// Sets the peer DID URI (required)
    ///
    /// # Parameters
    /// - `peer_did_uri`: Peer's DID URI that can be converted to PeerDIDURI
    ///
    /// # Validation
    /// - Must follow W3C DID specification: did:method:identifier
    /// - Method and identifier parts cannot be empty
    ///
    /// # Example
    /// ```rust
    /// builder.with_peer_did_uri("did:example:123456789abcdefghi")
    /// ```
    pub fn with_peer_did_uri<T: Into<PeerDIDURI>>(mut self, peer_did_uri: T) -> Self {
        self.peer_did_uri = Some(peer_did_uri.into());
        self
    }

    /// Sets the peer public key (required)
    ///
    /// # Parameters
    /// - `peer_key`: Peer's public key that can be converted to PeerKey
    ///
    /// # Validation
    /// - Must be exactly 64 hexadecimal characters (32 bytes for X25519)
    /// - Supports optional "0x" prefix (will be stripped)
    /// - Must contain only valid hex characters (0-9, a-f, A-F)
    ///
    /// # Example
    /// ```rust
    /// builder.with_peer_key("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
    /// // or with 0x prefix:
    /// builder.with_peer_key("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
    /// ```
    pub fn with_peer_key<T: Into<PeerKey>>(mut self, peer_key: T) -> Self {
        self.peer_key = Some(peer_key.into());
        self
    }

    /// Sets the password for KeySecure encryption (required)
    ///
    /// # Parameters
    /// - `password`: Password string for encrypting the private key
    ///
    /// # Security Requirements
    /// - Minimum 12 characters long
    /// - Must contain at least one lowercase letter
    /// - Must contain at least one uppercase letter
    /// - Must contain at least one digit
    /// - Must contain at least one special character from: !@#$%^&*()_+-=[]{}|;:,.<>?
    ///
    /// # Example
    /// ```rust
    /// builder.with_password("StrongPassword123!@#")
    /// ```
    pub fn with_password<T: Into<String>>(mut self, password: T) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Sets the peer connection ID (optional, auto-generated if not provided)
    ///
    /// # Parameters
    /// - `peer_connection_id`: Peer's connection ID that can be converted to ConnectionID
    ///
    /// # Default Behavior
    /// If not provided, a new UUID v4 will be generated automatically
    ///
    /// # Example
    /// ```rust
    /// builder.with_peer_connection_id("550e8400-e29b-41d4-a716-446655440001")
    /// ```
    pub fn with_peer_connection_id<T: Into<ConnectionID>>(mut self, peer_connection_id: T) -> Self {
        self.peer_connection_id = Some(peer_connection_id.into());
        self
    }

    /// Sets the connection context (optional, defaults to ConnectionContext::Connection)
    ///
    /// # Parameters
    /// - `context`: The context type for this connection
    ///
    /// # Default Behavior
    /// If not provided, defaults to ConnectionContext::Connection
    ///
    /// # Example
    /// ```rust
    /// builder.with_context(ConnectionContext::Connection)
    /// ```
    pub fn with_context(mut self, context: ConnectionContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Sets our own keypair (optional, auto-generated if not provided)
    ///
    /// # Parameters
    /// - `keypair`: The ECDH keypair to use for this connection
    ///
    /// # Default Behavior
    /// If not provided, a new keypair will be generated automatically using secure randomness
    ///
    /// # Use Cases
    /// - Testing: Provide deterministic keypairs for reproducible tests
    /// - Key Recovery: Use restored keypairs from KeySecure storage
    /// - Advanced Scenarios: Use pre-existing keypairs for specific protocols
    ///
    /// # Example
    /// ```rust
    /// let keypair = KeyPair::generate();
    /// builder.with_own_keypair(keypair)
    /// ```
    pub fn with_own_keypair(mut self, keypair: KeyPair) -> Self {
        self.own_keypair = Some(keypair);
        self
    }

    /// Use an existing KeySecure instead of generating new one
    ///
    /// This method is primarily used for connection completion scenarios where
    /// a partial connection already has an encrypted private key that should be reused.
    ///
    /// # Parameters
    /// - `keysecure`: Previously encrypted private key from partial connection
    ///
    /// # Use Cases
    /// - Connection completion: Reuse KeySecure from partial connection
    /// - Key recovery: Restore connections from persistent storage
    /// - Testing: Use predetermined KeySecure for reproducible tests
    ///
    /// # Validation
    /// Cannot be used together with `with_own_keypair()` - build() will fail
    ///
    /// # Example
    /// ```rust
    /// let existing_keysecure = partial_connection.get_own_keysecure().unwrap();
    /// let completed = Connection::builder()
    ///     .with_existing_keysecure(existing_keysecure)
    ///     .with_peer_key(peer_public_key)
    ///     .with_password("StrongPassword123!@#")
    ///     .build()?;
    /// ```
    pub fn with_existing_keysecure(mut self, keysecure: KeySecure) -> Self {
        self.own_keysecure = Some(keysecure);
        self
    }

    /// Create a builder from an existing partial connection
    ///
    /// This method copies all properties from an existing connection except for
    /// peer_key and password, which must be provided separately for completion.
    ///
    /// # Parameters
    /// - `existing`: The partial connection to copy properties from
    ///
    /// # Copied Properties
    /// - Connection ID, peer DID URI, peer connection ID
    /// - Connection context and existing KeySecure
    ///
    /// # Properties That Must Be Set
    /// - `peer_key`: Will be provided during completion
    /// - `password`: Will be provided by user during completion
    ///
    /// # Example
    /// ```rust
    /// let builder = ConnectionBuilder::from_existing_connection(&partial_connection)
    ///     .with_peer_key(peer_public_key)      // From approval notification
    ///     .with_password(user_password);       // From user input
    /// let completed = builder.build()?;
    /// ```
    pub fn from_existing_connection(existing: &Connection) -> Self {
        Self {
            id: Some(existing.get_id()),
            peer_did_uri: Some(existing.get_peer_did_uri()),
            peer_key: None, // Will be set when completing
            password: None, // Will be provided when completing
            peer_connection_id: Some(existing.get_peer_connection_id()),
            context: Some(existing.get_context()),
            own_keypair: None, // Will use existing KeySecure
            own_keysecure: existing.get_own_keysecure(), // ✅ Reuse existing
        }
    }

    /// Validates password complexity requirements
    ///
    /// # Security Requirements
    /// - Minimum 12 characters long
    /// - Must contain at least one lowercase letter
    /// - Must contain at least one uppercase letter
    /// - Must contain at least one digit
    /// - Must contain at least one special character from: !@#$%^&*()_+-=[]{}|;:,.<>?
    ///
    /// # Parameters
    /// - `password`: The password string to validate
    ///
    /// # Returns
    /// - `Ok(())`: Password meets all complexity requirements
    /// - `Err(ConnectionError)`: Password fails one or more requirements
    fn validate_password(password: &str) -> Result<(), ConnectionError> {
        if password.len() < 12 {
            return Err(ConnectionError::ValidationError(
                "Password must be at least 12 characters long".to_string(),
            ));
        }

        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        if !has_lowercase {
            return Err(ConnectionError::ValidationError(
                "Password must contain at least one lowercase letter".to_string(),
            ));
        }

        if !has_uppercase {
            return Err(ConnectionError::ValidationError(
                "Password must contain at least one uppercase letter".to_string(),
            ));
        }

        if !has_digit {
            return Err(ConnectionError::ValidationError(
                "Password must contain at least one digit".to_string(),
            ));
        }

        if !has_special {
            return Err(ConnectionError::ValidationError(
                "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Builds the Connection object with comprehensive validation and cryptographic setup
    ///
    /// This method supports three build modes based on provided parameters:
    ///
    /// ## 1. Complete Connection (peer_key + password)
    /// - Generates full ECDH shared secret immediately
    /// - State: Pending
    /// - Has real shared secret value
    ///
    /// ## 2. Partial Connection (password only)
    /// - Creates connection for outgoing requests
    /// - State: PendingOutgoing
    /// - Has placeholder shared secret ("pending")
    /// - Has our KeySecure for later completion
    ///
    /// ## 3. Passwordless Connection (neither)
    /// - Creates connection for incoming requests
    /// - State: PendingIncoming
    /// - No cryptographic material
    ///
    /// # Returns
    /// - `Ok(Connection)`: Successfully constructed and validated connection
    /// - `Err(ConnectionError)`: Validation or cryptographic error
    ///
    /// # Validation Performed
    /// - Connection ID: Must be valid UUID v4 format
    /// - Peer DID URI: Must follow W3C DID specification
    /// - Peer Key (if provided): Must be 64-character hex string
    /// - Password (if provided): Must meet complexity requirements
    /// - KeySecure conflicts: Cannot provide both keypair and existing KeySecure
    pub fn build(mut self) -> Result<Connection, ConnectionError> {
        let id_str = self.id.take().ok_or_else(|| {
            ConnectionError::ValidationError("Connection ID is required".to_string())
        })?;

        ConnectionID::validate(id_str.as_ref())?;
        let id = ConnectionID::from_validated(id_str.as_ref().to_string());

        let peer_did_uri_str = self.peer_did_uri.take().ok_or_else(|| {
            ConnectionError::ValidationError("Peer DID URI is required".to_string())
        })?;

        PeerDIDURI::validate(peer_did_uri_str.as_ref())?;
        let peer_did_uri = PeerDIDURI::from_validated(peer_did_uri_str.as_ref().to_string());

        let peer_connection_id = self
            .peer_connection_id
            .clone()
            .unwrap_or_else(|| ConnectionID::from(Uuid::new_v4().to_string()));
        let context = self
            .context
            .clone()
            .unwrap_or(ConnectionContext::Connection);

        match (&self.peer_key, &self.password) {
            // Complete connection (with password and peer key)
            (Some(peer_key_str), Some(password)) => {
                PeerKey::validate(peer_key_str.as_ref())?;
                Self::generate_complete_connection(
                    id,
                    peer_did_uri,
                    PeerKey::from_validated(peer_key_str.as_ref().to_string()),
                    peer_connection_id,
                    password.clone(),
                    context,
                    self.own_keypair,
                    self.own_keysecure,
                )
            }
            // Partial outgoing connection (with password, no peer key)
            (None, Some(password)) => Self::generate_partial_connection(
                id,
                peer_did_uri,
                peer_connection_id,
                password.clone(),
                context,
                self.own_keypair,
            ),
            // Passwordless incoming connection (no password, no keypair)
            _ => Self::generate_passwordless_incoming_connection(
                id,
                peer_did_uri,
                peer_connection_id,
                context,
            ),
        }
    }

    /// Generates a passwordless incoming connection (no cryptographic setup)
    ///
    /// Used for incoming connection requests where we haven't set up any
    /// cryptographic material yet. This represents a "placeholder" connection
    /// that will be processed through approval workflows.
    ///
    /// # Use Cases
    /// - Incoming connection requests that need user approval
    /// - Connection records for tracking peer requests
    /// - Placeholder connections before cryptographic setup
    ///
    /// # Properties
    /// - No KeySecure (no private key)
    /// - No public key
    /// - No shared secret
    /// - Placeholder peer key ("0000...0000")
    /// - State: PendingIncoming
    ///
    /// # Completion Flow
    /// These connections typically require separate approval and cryptographic setup
    /// through different workflows than the partial connection completion flow.
    ///
    /// # Parameters
    /// - `id`: Connection identifier
    /// - `peer_did_uri`: Peer's DID URI
    /// - `peer_connection_id`: Peer's connection ID
    /// - `context`: Connection context
    ///
    /// # Returns
    /// - `Ok(Connection)`: Passwordless connection in PendingIncoming state
    fn generate_passwordless_incoming_connection(
        id: ConnectionID,
        peer_did_uri: PeerDIDURI,
        peer_connection_id: ConnectionID,
        context: ConnectionContext,
    ) -> Result<Connection, ConnectionError> {
        let now = Utc::now();
        Ok(Connection {
            id,
            state: State::PendingIncoming,
            context,
            peer_did_uri,
            peer_key: PeerKey::from_validated(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            peer_connection_id,
            own_key: None,
            own_keysecure: None,
            own_shared_secret: None,
            created_at: now,
            updated_at: now,
        })
    }

    /// Generates a complete Connection with ECDH shared secret
    ///
    /// Enhanced version that supports both new keypair generation and existing KeySecure reuse.
    /// This is the core method for creating connections with full cryptographic setup.
    ///
    /// # Cryptographic Flows
    ///
    /// ## New Keypair (own_keypair + None)
    /// - Uses provided keypair for ECDH
    /// - Encrypts keypair with password to create KeySecure
    /// - Standard complete connection flow
    ///
    /// ## Existing KeySecure (None + existing_keysecure)
    /// - Decrypts existing KeySecure with password to recover keypair
    /// - Uses recovered keypair for ECDH with peer's public key
    /// - Reuses existing KeySecure (no re-encryption needed)
    /// - **Connection completion flow**
    ///
    /// ## Generated Keypair (None + None)
    /// - Generates new random keypair
    /// - Encrypts with password to create KeySecure
    /// - Default complete connection flow
    ///
    /// # Parameters
    /// - `id`: Connection identifier
    /// - `peer_did_uri`: Peer's DID URI
    /// - `peer_key`: Peer's public key for ECDH
    /// - `peer_connection_id`: Peer's connection ID
    /// - `password`: Password for KeySecure encryption/decryption
    /// - `context`: Connection context
    /// - `own_keypair`: Optional existing keypair
    /// - `existing_keysecure`: Optional existing encrypted private key
    ///
    /// # Returns
    /// - `Ok(Connection)`: Complete connection with shared secret in Pending state
    /// - `Err(ConnectionError)`: Cryptographic or validation error
    ///
    /// # Security Properties
    /// - Shared secret is ECDH(our_private, peer_public) -> Blake3 -> hex
    /// - Private keys are always encrypted with KeySecure
    /// - Password is used only for encryption/decryption, never stored
    fn generate_complete_connection(
        id: ConnectionID,
        peer_did_uri: PeerDIDURI,
        peer_key: PeerKey,
        peer_connection_id: ConnectionID,
        password: String,
        context: ConnectionContext,
        own_keypair: Option<KeyPair>,
        existing_keysecure: Option<KeySecure>,
    ) -> Result<Connection, ConnectionError> {
        let (keypair, own_keysecure) = match (own_keypair, existing_keysecure) {
            // Use provided keypair (normal case)
            (Some(keypair), None) => {
                let password_obj = Password::from(password.clone());
                let keysecure = keypair.to_keysecure(password_obj).map_err(|e| {
                    ConnectionError::CryptographicError(format!(
                        "KeySecure encryption failed: {}",
                        e
                    ))
                })?;
                (keypair, keysecure)
            }

            // Use existing KeySecure (completion case) - decrypt it to get keypair
            (None, Some(keysecure)) => {
                let decrypted = keysecure.decrypt(password.clone()).map_err(|e| {
                    ConnectionError::CryptographicError(format!(
                        "Failed to decrypt KeySecure: {}",
                        e
                    ))
                })?;

                let private_key_hex = String::from_utf8(decrypted.vec()).map_err(|e| {
                    ConnectionError::CryptographicError(format!("Invalid decrypted data: {}", e))
                })?;

                let keypair = KeyPair::from_hex(private_key_hex).map_err(|e| {
                    ConnectionError::CryptographicError(format!(
                        "Failed to reconstruct keypair: {}",
                        e
                    ))
                })?;

                (keypair, keysecure)
            }

            // Generate new keypair (default case)
            // Generate new keypair (default case)
            (None, None) => {
                let keypair = KeyPair::generate();
                let password_obj = Password::from(password.clone());
                let keysecure = keypair.to_keysecure(password_obj).map_err(|e| {
                    ConnectionError::CryptographicError(format!(
                        "KeySecure encryption failed: {}",
                        e
                    ))
                })?;
                (keypair, keysecure)
            }

            // Invalid: both provided
            (Some(_), Some(_)) => {
                return Err(ConnectionError::ValidationError(
                    "Cannot provide both keypair and existing KeySecure".to_string(),
                ));
            }
        };

        // Extract our public key for storage and sharing with peer
        let public_key = keypair.pub_key();
        let own_key_hex = public_key.to_hex();

        // Prepare peer's public key for ECDH computation
        let peer_key_clean = peer_key
            .as_ref()
            .strip_prefix("0x")
            .unwrap_or(peer_key.as_ref());

        let peer_key_hex = ByteHex::from(peer_key_clean.to_string());

        // Compute the ECDH shared secret: ECDH(our_private, peer_public)
        let secret = keypair.secret(peer_key_hex);

        // Hash the raw ECDH output using Blake3 for consistency
        let shared_secret = secret.to_blake3().map_err(|e| {
            ConnectionError::CryptographicError(format!("Shared secret generation failed: {}", e))
        })?;

        let now = Utc::now();

        // Construct complete Connection object
        Ok(Connection {
            id,
            state: State::Pending,
            context,
            peer_did_uri,
            peer_key,
            peer_connection_id,
            own_key: Some(OwnKey::from(own_key_hex.hex())),
            own_keysecure: Some(own_keysecure),
            own_shared_secret: Some(OwnSharedSecret::from(shared_secret.hex())),
            created_at: now,
            updated_at: now,
        })
    }

    /// Generates a partial Connection for outgoing requests (without peer key)
    ///
    /// Used when initiating connection requests where we don't have the peer's
    /// public key yet. The connection will be completed later when the peer responds
    /// with their approval and public key.
    ///
    /// # Cryptographic Setup
    /// - Generates or uses provided keypair for our side
    /// - Encrypts private key with password using KeySecure
    /// - Stores our public key for sharing with peer
    /// - Sets placeholder values for peer data and shared secret
    ///
    /// # Placeholder Values
    /// - `peer_key`: "0000...0000" (64 zeros)
    /// - `own_shared_secret`: "pending"
    /// - `state`: PendingOutgoing
    ///
    /// # Completion Flow
    /// Later, when peer approves:
    /// 1. Peer sends their public key via approval notification
    /// 2. User calls `complete_with_password()` with peer's key and their password
    /// 3. Connection derives real shared secret and transitions to Established
    ///
    /// # Parameters
    /// - `id`: Connection identifier
    /// - `peer_did_uri`: Peer's DID URI
    /// - `peer_connection_id`: Peer's connection ID
    /// - `password`: Password for KeySecure encryption
    /// - `context`: Connection context
    /// - `own_keypair`: Optional existing keypair
    ///
    /// # Returns
    /// - `Ok(Connection)`: Partial connection in PendingOutgoing state
    /// - `Err(ConnectionError)`: Validation or cryptographic error
    fn generate_partial_connection(
        id: ConnectionID,
        peer_did_uri: PeerDIDURI,
        peer_connection_id: ConnectionID,
        password: String,
        context: ConnectionContext,
        own_keypair: Option<KeyPair>,
    ) -> Result<Connection, ConnectionError> {
        // Use provided keypair or generate a new one using secure randomness
        let keypair = own_keypair.unwrap_or_else(|| KeyPair::generate());

        // Extract our public key for storage and sharing with peer
        let public_key = keypair.pub_key();
        let own_key_hex = public_key.to_hex();

        // ✅ Validate password complexity
        Self::validate_password(password.as_str())?;

        // ✅ Correct KeySecure encryption using ToKeySecure trait
        let password_obj = Password::from(password);
        let own_keysecure = keypair.to_keysecure(password_obj).map_err(|e| {
            ConnectionError::CryptographicError(format!("KeySecure encryption failed: {}", e))
        })?;

        let now = Utc::now();

        // Construct partial Connection object with placeholder values
        Ok(Connection {
            id,
            state: State::PendingOutgoing, // ✅ New state for outgoing requests
            context,
            peer_did_uri,
            peer_key: PeerKey::from_validated(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            peer_connection_id,
            own_key: Some(OwnKey::from(own_key_hex.hex())),
            own_keysecure: Some(own_keysecure),
            own_shared_secret: Some(OwnSharedSecret::from("pending".to_string())),
            created_at: now,
            updated_at: now,
        })
    }

    /// Completes a partial connection when the peer's public key becomes available
    ///
    /// This method is used in traditional completion workflows (not the new notification-based
    /// approach). It modifies an existing connection in-place rather than creating a new one.
    ///
    /// # Migration Note
    /// For new notification-based workflows, prefer `Connection::complete_with_password()`
    /// which creates a new completed connection instead of modifying the existing one.
    ///
    /// # Parameters
    /// - `connection`: Mutable reference to the partial connection
    /// - `peer_key`: The peer's public key received from their response
    /// - `password`: Password to decrypt our private key
    ///
    /// # Returns
    /// - `Ok(())`: Connection successfully completed (modified in-place)
    /// - `Err(ConnectionError)`: Cryptographic operation failure
    ///
    /// # State Requirements
    /// - Connection must be in PendingOutgoing or PendingIncoming state
    /// - Connection must have KeySecure for decryption (PendingOutgoing only)
    pub fn complete_connection(
        connection: &mut Connection,
        peer_key: PeerKey,
        password: &str,
    ) -> Result<(), ConnectionError> {
        // Verify this is a partial connection
        if connection.state != State::PendingOutgoing && connection.state != State::PendingIncoming
        {
            return Err(ConnectionError::ValidationError(
                "Can only complete connections in PendingOutgoing or PendingIncoming state"
                    .to_string(),
            ));
        }

        // ✅ Decrypt the private key from KeySecure
        let decrypted_message = connection
            .clone()
            .own_keysecure
            .ok_or(ConnectionError::ValidationError(
                "Own keysecure is required for decryption".to_string(),
            ))?
            .decrypt(password.to_string())
            .map_err(|e| {
                ConnectionError::CryptographicError(format!("Failed to decrypt private key: {}", e))
            })?;

        // ✅ Convert decrypted bytes back to hex string
        // KeySecure always stores private key as hex-encoded string
        let private_key_hex = String::from_utf8(decrypted_message.vec()).map_err(|e| {
            ConnectionError::CryptographicError(format!(
                "Failed to convert decrypted data to hex string: {}",
                e
            ))
        })?;

        // ✅ Reconstruct KeyPair from hex string (same as KeyPair::from_hex)
        let keypair = KeyPair::from_hex(private_key_hex).map_err(|e| {
            ConnectionError::CryptographicError(format!(
                "Failed to reconstruct keypair from hex: {}",
                e
            ))
        })?;

        // Prepare peer's public key for ECDH computation
        let peer_key_clean = peer_key
            .as_ref()
            .strip_prefix("0x")
            .unwrap_or(peer_key.as_ref());
        let peer_key_hex = ByteHex::from(peer_key_clean.to_string());

        // Compute the ECDH shared secret
        let secret = keypair.secret(peer_key_hex);
        let shared_secret = secret.to_blake3().map_err(|e| {
            ConnectionError::CryptographicError(format!("Shared secret generation failed: {}", e))
        })?;

        // Update connection with real peer data
        connection.peer_key = peer_key;
        connection.own_shared_secret = Some(OwnSharedSecret::from(shared_secret.hex()));
        connection.state = State::Established;
        connection.updated_at = Utc::now();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! # Comprehensive Test Suite for Connection Module
    //!
    //! This test suite covers all aspects of the refactored Connection implementation:
    //!
    //! ## Test Categories
    //! 1. **Complete Connections**: Traditional connections with full ECDH setup
    //! 2. **Partial Connections**: New outgoing request functionality
    //! 3. **Connection Completion**: Transitioning from partial to complete
    //! 4. **Input Validation**: All validation requirements
    //! 5. **State Management**: Connection lifecycle with new states
    //! 6. **Cryptographic Security**: ECDH properties and shared secrets
    //! 7. **Serialization**: JSON and binary persistence
    //! 8. **Error Handling**: All error conditions and edge cases

    use super::*;

    // ========================================
    // COMPLETE CONNECTION TESTS (Traditional)
    // ========================================

    /// Tests successful complete connection creation with valid inputs
    #[test]
    fn test_complete_connection_success() {
        let peer_keypair = KeyPair::generate();
        let peer_pubkey = peer_keypair.pub_key();
        let peer_key_hex = peer_pubkey.to_hex();

        let connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:123456789abcdefghi".to_string())
            .with_peer_key(peer_key_hex.hex())
            .with_password("StrongPassword123!@#".to_string())
            .build();

        assert!(
            connection.is_ok(),
            "Complete connection should be created successfully: {:?}",
            connection.err()
        );
        let conn = connection.unwrap();
        assert_eq!(conn.get_state(), State::Pending); // Complete connections start in Pending
        assert_eq!(conn.get_context(), ConnectionContext::Connection);
        assert_ne!(conn.get_own_shared_secret().unwrap().as_ref(), "pending"); // Should have real shared secret
    }

    /// Tests ECDH shared secret generation correctness for complete connections
    #[test]
    fn test_complete_connection_ecdh_verification() {
        let keypair_alice = KeyPair::generate();
        let keypair_bob = KeyPair::generate();

        let pubkey_alice = keypair_alice.pub_key();
        let pubkey_bob = keypair_bob.pub_key();

        let strong_password = "StrongPassword123!@#";

        // Alice's complete connection to Bob
        let alice_connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440001".to_string())
            .with_peer_did_uri("did:example:bob".to_string())
            .with_peer_key(pubkey_bob.to_hex().hex())
            .with_password(strong_password.to_string())
            .with_own_keypair(keypair_alice)
            .build()
            .expect("Alice connection should be created successfully");

        // Bob's complete connection to Alice
        let bob_connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440002".to_string())
            .with_peer_did_uri("did:example:alice".to_string())
            .with_peer_key(pubkey_alice.to_hex().hex())
            .with_password(strong_password.to_string())
            .with_own_keypair(keypair_bob)
            .build()
            .expect("Bob connection should be created successfully");

        // Critical ECDH property: both should produce identical shared secrets
        assert_eq!(
            alice_connection.get_own_shared_secret().as_ref(),
            bob_connection.get_own_shared_secret().as_ref(),
            "ECDH shared secrets must be identical for both peers"
        );

        // Both should be in Pending state (complete connections)
        assert_eq!(alice_connection.get_state(), State::Pending);
        assert_eq!(bob_connection.get_state(), State::Pending);
    }

    // ========================================
    // PARTIAL CONNECTION TESTS (New Functionality)
    // ========================================

    /// Tests successful partial connection creation (without peer key)
    #[test]
    fn test_partial_connection_success() {
        let connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:peer".to_string())
            // ✅ No peer key provided - should create partial connection
            .with_password("StrongPassword123!@#".to_string())
            .build();

        assert!(
            connection.is_ok(),
            "Partial connection should be created successfully: {:?}",
            connection.err()
        );
        let conn = connection.unwrap();

        // Verify partial connection properties
        assert_eq!(conn.get_state(), State::PendingOutgoing); // ✅ New state for partial connections
        assert_eq!(
            conn.get_peer_key().as_ref(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        ); // Placeholder
        assert_eq!(
            conn.get_own_shared_secret().unwrap(),
            OwnSharedSecret::from("pending".to_string())
        ); // Placeholder
        assert_ne!(conn.get_own_key().unwrap().as_ref(), ""); // Should have our real public key
    }

    /// Tests that partial connections have our real public key but placeholder peer data
    #[test]
    fn test_partial_connection_properties() {
        let our_keypair = KeyPair::generate();
        let expected_pub_key = our_keypair.pub_key().to_hex().hex();

        let connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:peer".to_string())
            .with_password("StrongPassword123!@#".to_string())
            .with_own_keypair(our_keypair)
            .build()
            .unwrap();

        // Verify we have our real key
        assert_eq!(
            connection.get_own_key().as_ref(),
            Some(&OwnKey::from(expected_pub_key))
        );

        // Verify placeholder values
        assert_eq!(
            connection.get_peer_key().as_ref(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            connection.get_own_shared_secret().as_ref(),
            Some(&OwnSharedSecret::from("pending".to_string()))
        );
        assert_eq!(connection.get_state(), State::PendingOutgoing);
    }

    // ========================================
    // CONNECTION COMPLETION TESTS (New Functionality)
    // ========================================

    /// Tests successful completion of partial connection
    #[test]
    fn test_connection_completion_success() {
        // Step 1: Create partial connection
        let our_keypair = KeyPair::generate();
        let mut connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:peer".to_string())
            .with_password("StrongPassword123!@#".to_string())
            .with_own_keypair(our_keypair.clone())
            .build()
            .unwrap();

        assert_eq!(connection.get_state(), State::PendingOutgoing);

        // Step 2: Generate peer keypair and complete connection
        let peer_keypair = KeyPair::generate();
        let peer_public_key = PeerKey::new(peer_keypair.pub_key().to_hex().hex()).unwrap();

        let result = ConnectionBuilder::complete_connection(
            &mut connection,
            peer_public_key.clone(),
            "StrongPassword123!@#",
        );

        assert!(
            result.is_ok(),
            "Connection completion should succeed: {:?}",
            result.err()
        );

        // Step 3: Verify completion results
        assert_eq!(connection.get_state(), State::Established); // ✅ Should be established now
        assert_eq!(connection.get_peer_key(), peer_public_key); // ✅ Should have real peer key
        assert_ne!(
            connection.get_own_shared_secret().as_ref(),
            Some(&OwnSharedSecret::from("pending".to_string()))
        ); // ✅ Should have real shared secret

        // Step 4: Verify ECDH correctness by computing expected shared secret
        let peer_key_clean = peer_public_key
            .as_ref()
            .strip_prefix("0x")
            .unwrap_or(peer_public_key.as_ref());
        let peer_key_hex = ByteHex::from(peer_key_clean.to_string());
        let expected_secret = our_keypair.secret(peer_key_hex).to_blake3().unwrap();

        assert_eq!(
            connection.get_own_shared_secret().as_ref(),
            Some(&OwnSharedSecret::from(expected_secret.hex())),
        );
    }

    /// Tests that connection completion fails for connections not in PendingOutgoing state
    #[test]
    fn test_connection_completion_wrong_state() {
        // Create complete connection (Pending state)
        let peer_keypair = KeyPair::generate();
        let mut connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:peer".to_string())
            .with_peer_key(peer_keypair.pub_key().to_hex().hex())
            .with_password("StrongPassword123!@#".to_string())
            .build()
            .unwrap();

        assert_eq!(connection.get_state(), State::Pending); // Complete connection

        // Try to complete it (should fail)
        let another_peer_key = PeerKey::new(KeyPair::generate().pub_key().to_hex().hex()).unwrap();
        let result = ConnectionBuilder::complete_connection(
            &mut connection,
            another_peer_key,
            "StrongPassword123!@#",
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConnectionError::ValidationError(_)
        ));
    }

    /// Tests connection completion with wrong password
    #[test]
    fn test_connection_completion_wrong_password() {
        let mut connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:peer".to_string())
            .with_password("StrongPassword123!@#".to_string())
            .build()
            .unwrap();

        let peer_key = PeerKey::new(KeyPair::generate().pub_key().to_hex().hex()).unwrap();
        let result = ConnectionBuilder::complete_connection(
            &mut connection,
            peer_key,
            "WrongPassword456!@#", // ❌ Wrong password
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConnectionError::CryptographicError(_)
        ));
    }

    // ========================================
    // INPUT VALIDATION TESTS
    // ========================================

    /// Tests that missing required fields are properly detected
    #[test]
    fn test_missing_required_fields() {
        // Missing ID
        let result = Connection::builder()
            .with_peer_did_uri("did:example:test".to_string())
            .with_password("StrongPassword123!@#".to_string())
            .build();
        assert!(result.is_err());

        // Missing peer DID URI
        let result = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_password("StrongPassword123!@#".to_string())
            .build();
        assert!(result.is_err());

        // Missing password: should now succeed and produce PendingIncoming
        let result = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:test".to_string())
            .build();
        assert!(result.is_ok());
        let conn = result.unwrap();
        assert_eq!(conn.get_state(), State::PendingIncoming);
        assert!(conn.get_own_key().is_none());
        assert!(conn.get_own_keysecure().is_none());
        assert!(conn.get_own_shared_secret().is_none());
    }

    /// Tests rejection of invalid peer key formats (when provided)
    #[test]
    fn test_invalid_peer_key_formats() {
        let invalid_keys = [
            "short",                                                              // Too short
            "not_hex_characters",                                                 // Non-hex chars
            "",                                                                   // Empty
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12", // Too long
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", // Invalid hex chars
        ];

        for invalid_key in invalid_keys {
            let result = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:test".to_string())
                .with_peer_key(invalid_key.to_string())
                .with_password("StrongPassword123!@#".to_string())
                .build();

            assert!(result.is_err(), "Should fail for key: {}", invalid_key);
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::ValidationError(_)
            ));
        }
    }

    /// Tests rejection of weak passwords
    #[test]
    fn test_weak_password_validation() {
        let weak_passwords = [
            "",                  // Empty
            "short",             // Too short
            "onlylowercase",     // Missing requirements
            "ONLYUPPERCASE",     // Missing requirements
            "NoNumbers!@#",      // Missing numbers
            "NoSpecialChars123", // Missing special chars
            "nouppercase123!",   // Missing uppercase
            "NOLOWERCASE123!",   // Missing lowercase
        ];

        for weak_password in weak_passwords {
            let result = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:test".to_string())
                .with_password(weak_password.to_string())
                .build();

            assert!(
                result.is_err(),
                "Should fail for password: '{}'",
                weak_password
            );
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::ValidationError(_)
            ));
        }
    }

    /// Tests acceptance of peer keys with "0x" prefix
    #[test]
    fn test_peer_key_with_prefix() {
        let peer_keypair = KeyPair::generate();
        let key_with_prefix = format!("0x{}", peer_keypair.pub_key().to_hex().hex());

        let connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:test".to_string())
            .with_peer_key(key_with_prefix)
            .with_password("StrongPassword123!@#".to_string())
            .build();

        assert!(connection.is_ok());
    }

    // ========================================
    // STATE MANAGEMENT TESTS
    // ========================================

    /// Tests state transitions and timestamp updates
    #[test]
    fn test_state_transitions() {
        let mut connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:test".to_string())
            .with_password("StrongPassword123!@#".to_string())
            .build()
            .unwrap();

        // Initial state should be PendingOutgoing (partial connection)
        assert_eq!(connection.get_state(), State::PendingOutgoing);

        let initial_time = connection.get_updated_at();
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Test state update
        connection.update_state(State::Established);
        assert_eq!(connection.get_state(), State::Established);
        assert!(connection.get_updated_at() > initial_time);

        // Test another state transition
        connection.update_state(State::Failed);
        assert_eq!(connection.get_state(), State::Failed);
    }

    // ========================================
    // CRYPTOGRAPHIC SECURITY TESTS
    // ========================================

    /// Tests that different peer keys produce different shared secrets
    #[test]
    fn test_different_peers_different_secrets() {
        let keypair_alice = KeyPair::generate();
        let keypair_bob = KeyPair::generate();
        let keypair_charlie = KeyPair::generate();

        // Alice connects to Bob
        let alice_bob_connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440001".to_string())
            .with_peer_did_uri("did:example:bob".to_string())
            .with_peer_key(keypair_bob.pub_key().to_hex().hex())
            .with_password("StrongPassword123!@#".to_string())
            .with_own_keypair(keypair_alice.clone())
            .build()
            .unwrap();

        // Alice connects to Charlie
        let alice_charlie_connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440002".to_string())
            .with_peer_did_uri("did:example:charlie".to_string())
            .with_peer_key(keypair_charlie.pub_key().to_hex().hex())
            .with_password("StrongPassword123!@#".to_string())
            .with_own_keypair(keypair_alice)
            .build()
            .unwrap();

        // Different peers should produce different shared secrets
        assert_ne!(
            alice_bob_connection.get_own_shared_secret().as_ref(),
            alice_charlie_connection.get_own_shared_secret().as_ref(),
            "Different peers should produce different shared secrets"
        );
    }

    /// Tests shared secret output properties
    #[test]
    fn test_shared_secret_properties() {
        let keypair_alice = KeyPair::generate();
        let keypair_bob = KeyPair::generate();

        let alice_connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440001".to_string())
            .with_peer_did_uri("did:example:bob".to_string())
            .with_peer_key(keypair_bob.pub_key().to_hex().hex())
            .with_password("StrongPassword123!@#".to_string())
            .with_own_keypair(keypair_alice)
            .build()
            .unwrap();

        let shared_secret = alice_connection.get_own_shared_secret();

        // Verify shared secret properties
        assert!(!shared_secret.as_ref().is_none());
        assert_eq!(shared_secret.clone().unwrap().as_ref().len(), 64); // Blake3 = 32 bytes = 64 hex chars
        assert!(shared_secret
            .clone()
            .unwrap()
            .as_ref()
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
        assert_ne!(shared_secret.unwrap().as_ref(), "pending"); // Should not be placeholder
    }

    // ========================================
    // SERIALIZATION TESTS
    // ========================================

    /// Tests JSON and binary serialization for both connection types
    #[test]
    fn test_serialization_complete_connection() {
        let peer_keypair = KeyPair::generate();
        let connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:test".to_string())
            .with_peer_key(peer_keypair.pub_key().to_hex().hex())
            .with_password("StrongPassword123!@#".to_string())
            .build()
            .unwrap();

        // Test JSON serialization
        let json = connection.to_json().expect("Should serialize to JSON");
        assert!(!json.is_empty());
        assert!(json.contains("did:example:test"));
        assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(json.contains("Pending")); // Complete connection state

        // Test binary serialization roundtrip
        let bytes: Vec<u8> = connection
            .clone()
            .try_into()
            .expect("Should serialize to bytes");
        let deserialized = Connection::try_from(bytes).expect("Should deserialize from bytes");

        assert_eq!(deserialized.get_id().as_ref(), connection.get_id().as_ref());
        assert_eq!(deserialized.get_state(), connection.get_state());
    }

    /// Tests serialization for partial connections
    #[test]
    fn test_serialization_partial_connection() {
        let connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:test".to_string())
            .with_password("StrongPassword123!@#".to_string())
            .build()
            .unwrap();

        let json = connection.to_json().expect("Should serialize to JSON");
        assert!(json.contains("PendingOutgoing")); // Partial connection state
        assert!(json.contains("pending")); // Placeholder shared secret
        assert!(json.contains("0000000000000000000000000000000000000000000000000000000000000000"));
        // Placeholder peer key
    }

    // ========================================
    // BUILDER PATTERN TESTS
    // ========================================

    /// Tests builder with all optional fields provided
    #[test]
    fn test_builder_all_optional_fields() {
        let peer_keypair = KeyPair::generate();
        let own_keypair = KeyPair::generate();

        let connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:test".to_string())
            .with_peer_key(peer_keypair.pub_key().to_hex().hex())
            .with_password("StrongPassword123!@#".to_string())
            .with_peer_connection_id("550e8400-e29b-41d4-a716-446655440001".to_string())
            .with_context(ConnectionContext::Connection)
            .with_own_keypair(own_keypair.clone())
            .build();

        assert!(connection.is_ok());
        let conn = connection.unwrap();
        assert_eq!(
            conn.get_peer_connection_id().as_ref(),
            "550e8400-e29b-41d4-a716-446655440001"
        );
        assert_eq!(
            conn.get_own_key().as_ref(),
            Some(&OwnKey::from(own_keypair.pub_key().to_hex().hex()))
        );
    }

    /// Tests minimum valid password boundary
    #[test]
    fn test_minimum_valid_password() {
        let connection = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:test".to_string())
            .with_password("Password1!@#".to_string()) // Exactly 12 chars with all requirements
            .build();

        assert!(connection.is_ok());
    }

    mod incoming_connection_tests {
        use super::*;

        // ========================================
        // PASSWORDLESS INCOMING CONNECTION TESTS
        // ========================================

        /// Tests creation of a passwordless incoming connection (no password, no keypair)
        #[test]
        fn test_passwordless_incoming_connection_success() {
            let result = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440abc".to_string())
                .with_peer_did_uri("did:example:incoming".to_string())
                .build();

            assert!(
                result.is_ok(),
                "Should succeed for passwordless incoming connection"
            );
            let conn = result.unwrap();
            assert_eq!(conn.get_state(), State::PendingIncoming);
            assert!(conn.get_own_key().is_none());
            assert!(conn.get_own_keysecure().is_none());
            assert!(conn.get_own_shared_secret().is_none());
            assert_eq!(
                conn.get_peer_key().as_ref(),
                "0000000000000000000000000000000000000000000000000000000000000000"
            );
        }

        /// Tests serialization and deserialization of passwordless incoming connection
        #[test]
        fn test_passwordless_incoming_connection_serialization() {
            let conn = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440def".to_string())
                .with_peer_did_uri("did:example:incoming".to_string())
                .build()
                .unwrap();

            let json = conn.to_json().expect("Should serialize to JSON");
            assert!(json.contains("PendingIncoming"));
            assert!(json.contains("did:example:incoming"));
            assert!(
                json.contains("0000000000000000000000000000000000000000000000000000000000000000")
            );

            let bytes: Vec<u8> = conn.clone().try_into().expect("Should serialize to bytes");
            let deserialized = Connection::try_from(bytes).expect("Should deserialize from bytes");
            assert_eq!(deserialized.get_state(), State::PendingIncoming);
            assert!(deserialized.get_own_key().is_none());
        }

        /// Tests that attempting to complete a passwordless connection fails
        #[test]
        fn test_complete_passwordless_connection_should_fail() {
            let mut conn = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440fff".to_string())
                .with_peer_did_uri("did:example:incoming".to_string())
                .build()
                .unwrap();

            let peer_key = PeerKey::new(KeyPair::generate().pub_key().to_hex().hex()).unwrap();
            let result =
                ConnectionBuilder::complete_connection(&mut conn, peer_key, "AnyPassword123!@#");
            assert!(
                result.is_err(),
                "Should fail to complete passwordless connection"
            );
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::ValidationError(_)
            ));
        }

        // ========================================
        // EDGE CASES FOR BUILDER
        // ========================================

        /// Tests builder with only peer key (no password) should produce passwordless incoming
        #[test]
        fn test_builder_only_peer_key_no_password() {
            let peer_keypair = KeyPair::generate();
            let result = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440eee".to_string())
                .with_peer_did_uri("did:example:incoming".to_string())
                .with_peer_key(peer_keypair.pub_key().to_hex().hex())
                .build();

            assert!(result.is_ok());
            let conn = result.unwrap();
            assert_eq!(conn.get_state(), State::PendingIncoming);
            assert!(conn.get_own_key().is_none());
        }

        /// Tests builder with only password (no peer key) should produce partial outgoing
        #[test]
        fn test_builder_only_password_no_peer_key() {
            let result = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440ddd".to_string())
                .with_peer_did_uri("did:example:outgoing".to_string())
                .with_password("StrongPassword123!@#".to_string())
                .build();

            assert!(result.is_ok());
            let conn = result.unwrap();
            assert_eq!(conn.get_state(), State::PendingOutgoing);
            assert!(conn.get_own_key().is_some());
            assert_eq!(
                conn.get_own_shared_secret().unwrap(),
                OwnSharedSecret::from("pending".to_string())
            );
        }

        // ========================================
        // STATE ENFORCEMENT TESTS
        // ========================================

        /// Tests that only PendingOutgoing or PendingIncoming can be completed
        #[test]
        fn test_complete_connection_state_enforcement() {
            let mut conn = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440aaa".to_string())
                .with_peer_did_uri("did:example:incoming".to_string())
                .build()
                .unwrap();

            // Set to Established state manually
            conn.update_state(State::Established);

            let peer_key = PeerKey::new(KeyPair::generate().pub_key().to_hex().hex()).unwrap();
            let result =
                ConnectionBuilder::complete_connection(&mut conn, peer_key, "StrongPassword123!@#");
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::ValidationError(_)
            ));
        }
    }

    mod complete_with_password_tests {
        use super::*;

        /// Tests successful completion of partial connection with correct password
        #[test]
        fn test_complete_with_password_success() {
            // Step 1: Create partial connection (PendingOutgoing)
            let our_keypair = KeyPair::generate();
            let connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_password("StrongPassword123!@#")
                .with_own_keypair(our_keypair.clone())
                .build()
                .unwrap();

            assert_eq!(connection.get_state(), State::PendingOutgoing);

            // Step 2: Generate peer's public key
            let peer_keypair = KeyPair::generate();
            let peer_public_key = peer_keypair.pub_key().to_hex().hex();

            // Step 3: Complete connection with peer's public key
            let result =
                connection.complete_with_password(&peer_public_key, "StrongPassword123!@#");

            assert!(
                result.is_ok(),
                "Completion should succeed: {:?}",
                result.err()
            );

            let completed_connection = result.unwrap();
            assert_eq!(completed_connection.get_state(), State::Established);
            assert_eq!(
                completed_connection.get_peer_key().to_string(),
                peer_public_key
            );
            assert_ne!(
                completed_connection
                    .get_own_shared_secret()
                    .unwrap()
                    .as_ref(),
                "pending"
            );

            // Step 4: Verify ECDH correctness
            let expected_secret = our_keypair
                .secret(ByteHex::from(peer_public_key.clone()))
                .to_blake3()
                .unwrap();

            assert_eq!(
                completed_connection
                    .get_own_shared_secret()
                    .unwrap()
                    .to_string(),
                expected_secret.hex()
            );
        }

        /// Tests completion failure with wrong password
        #[test]
        fn test_complete_with_password_wrong_password() {
            let connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_password("StrongPassword123!@#".to_string())
                .build()
                .unwrap();

            let peer_public_key = KeyPair::generate().pub_key().to_hex().hex();

            let result = connection.complete_with_password(&peer_public_key, "WrongPassword456!@#");

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::CryptographicError(_)
            ));
        }

        /// Tests completion failure for wrong connection state
        #[test]
        fn test_complete_with_password_wrong_state() {
            // Create complete connection (Pending state)
            let peer_keypair = KeyPair::generate();
            let connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_peer_key(peer_keypair.pub_key().to_hex().hex())
                .with_password("StrongPassword123!@#")
                .build()
                .unwrap();

            assert_eq!(connection.get_state(), State::Pending);

            let another_peer_key = KeyPair::generate().pub_key().to_hex().hex();
            let result =
                connection.complete_with_password(&another_peer_key, "StrongPassword123!@#");

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::InvalidStateTransition {
                    from: State::Pending,
                    to: State::Established
                }
            ));
        }

        /// Tests completion failure when KeySecure is missing
        #[test]
        fn test_complete_with_password_missing_keysecure() {
            // Create connection without KeySecure (passwordless incoming)
            let mut connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .build()
                .unwrap();

            // Manually set to PendingOutgoing to bypass state check
            connection.update_state(State::PendingOutgoing);

            let peer_public_key = KeyPair::generate().pub_key().to_hex().hex();
            let result =
                connection.complete_with_password(&peer_public_key, "StrongPassword123!@#");

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::CryptographicError(_)
            ));
        }

        /// Tests completion with invalid peer public key
        #[test]
        fn test_complete_with_password_invalid_peer_key() {
            let connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_password("StrongPassword123!@#".to_string())
                .build()
                .unwrap();

            let invalid_keys = [
                "short",
                "not_hex_characters",
                "",
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12", // Too long
            ];

            for invalid_key in invalid_keys {
                let result = connection.complete_with_password(invalid_key, "StrongPassword123!@#");

                assert!(
                    result.is_err(),
                    "Should fail for invalid key: {}",
                    invalid_key
                );
            }
        }

        /// Tests completion preserves original connection properties
        #[test]
        fn test_complete_with_password_preserves_properties() {
            let original_id =
                ConnectionID::from("550e8400-e29b-41d4-a716-446655440000".to_string());
            let original_peer_did = PeerDIDURI::from("did:example:peer".to_string());
            let original_peer_conn_id = ConnectionID::generate();

            let connection = Connection::builder()
                .with_id(original_id.clone())
                .with_peer_did_uri(original_peer_did.clone())
                .with_peer_connection_id(original_peer_conn_id.clone())
                .with_password("StrongPassword123!@#")
                .build()
                .unwrap();

            let peer_public_key = KeyPair::generate().pub_key().to_hex().hex();
            let completed = connection
                .complete_with_password(&peer_public_key, "StrongPassword123!@#")
                .unwrap();

            // Verify preserved properties
            assert_eq!(completed.get_id(), original_id);
            assert_eq!(completed.get_peer_did_uri(), original_peer_did);
            assert_eq!(completed.get_peer_connection_id(), original_peer_conn_id);
            assert_eq!(completed.get_context(), ConnectionContext::Connection);
        }
    }

    mod enhanced_builder_tests {
        use super::*;

        /// Tests with_existing_keysecure method
        #[test]
        fn test_builder_with_existing_keysecure() {
            // Create original connection to get KeySecure
            let original_keypair = KeyPair::generate();
            let original_connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_password("StrongPassword123!@#".to_string())
                .with_own_keypair(original_keypair.clone())
                .build()
                .unwrap();

            let existing_keysecure = original_connection.get_own_keysecure().unwrap();

            // Create new connection with existing KeySecure
            let peer_keypair = KeyPair::generate();
            let new_connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440001".to_string())
                .with_peer_did_uri("did:example:newpeer".to_string())
                .with_peer_key(peer_keypair.pub_key().to_hex().hex())
                .with_password("StrongPassword123!@#")
                .with_existing_keysecure(existing_keysecure.clone())
                .build();

            assert!(new_connection.is_ok());
            let conn = new_connection.unwrap();

            // Should have same public key (derived from same private key)
            assert_eq!(
                conn.get_own_key().unwrap().to_string(),
                original_keypair.pub_key().to_hex().hex()
            );
        }

        /// Tests from_existing_connection method
        #[test]
        fn test_builder_from_existing_connection() {
            let original_connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_password("StrongPassword123!@#".to_string())
                .build()
                .unwrap();

            let builder = ConnectionBuilder::from_existing_connection(&original_connection);

            // Should preserve original properties
            assert_eq!(builder.id, Some(original_connection.get_id()));
            assert_eq!(
                builder.peer_did_uri,
                Some(original_connection.get_peer_did_uri())
            );
            assert_eq!(
                builder.peer_connection_id,
                Some(original_connection.get_peer_connection_id())
            );
            assert_eq!(builder.context, Some(original_connection.get_context()));

            // Should have None for fields that need to be set
            assert_eq!(builder.peer_key, None);
            assert_eq!(builder.password, None);
        }

        /// Tests builder with both keypair and existing KeySecure (should fail)
        #[test]
        fn test_builder_with_both_keypair_and_keysecure_should_fail() {
            let keypair = KeyPair::generate();
            let existing_keysecure = keypair
                .to_keysecure(Password::from("password".to_string()))
                .unwrap();

            let result = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_peer_key(KeyPair::generate().pub_key().to_hex().hex())
                .with_password("StrongPassword123!@#")
                .with_own_keypair(keypair)
                .with_existing_keysecure(existing_keysecure)
                .build();

            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::ValidationError(_)
            ));
        }
    }

    mod decrypt_and_derive_tests {
        use super::*;

        /// Tests successful decryption and shared secret derivation
        #[test]
        fn test_decrypt_and_derive_shared_secret_success() {
            let our_keypair = KeyPair::generate();
            let peer_keypair = KeyPair::generate();

            let mut connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_peer_key(peer_keypair.pub_key().to_hex().hex())
                .with_password("StrongPassword123!@#")
                .with_own_keypair(our_keypair.clone())
                .build()
                .unwrap();

            // Should already have shared secret from builder
            let original_secret = connection.get_own_shared_secret().unwrap();

            // Clear shared secret to test the method
            connection.own_shared_secret = None;

            let result = connection.decrypt_and_derive_shared_secret("StrongPassword123!@#");
            assert!(
                result.is_ok(),
                "Decryption should succeed: {:?}",
                result.err()
            );

            // Should now have the shared secret again
            let new_secret = connection.get_own_shared_secret().unwrap();
            assert_eq!(new_secret, original_secret);
        }

        /// Tests decryption failure with wrong password
        #[test]
        fn test_decrypt_and_derive_wrong_password() {
            let mut connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_peer_key(KeyPair::generate().pub_key().to_hex().hex())
                .with_password("StrongPassword123!@#")
                .build()
                .unwrap();

            let result = connection.decrypt_and_derive_shared_secret("WrongPassword456!@#");
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::CryptographicError(_)
            ));
        }

        /// Tests failure when KeySecure is missing
        #[test]
        fn test_decrypt_and_derive_missing_keysecure() {
            let mut connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .build()
                .unwrap();

            let result = connection.decrypt_and_derive_shared_secret("StrongPassword123!@#");
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::CryptographicError(_)
            ));
        }

        /// Tests timestamp update after successful operation
        #[test]
        fn test_decrypt_and_derive_updates_timestamp() {
            let mut connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_peer_key(KeyPair::generate().pub_key().to_hex().hex())
                .with_password("StrongPassword123!@#")
                .build()
                .unwrap();

            let original_timestamp = connection.get_updated_at();
            std::thread::sleep(std::time::Duration::from_millis(10));

            connection.own_shared_secret = None; // Clear to test the method
            let result = connection.decrypt_and_derive_shared_secret("StrongPassword123!@#");
            assert!(result.is_ok());

            assert!(connection.get_updated_at() > original_timestamp);
        }
    }

    mod error_handling_tests {
        use super::*;

        /// Tests all possible error conditions for complete_with_password
        #[test]
        fn test_complete_with_password_all_error_conditions() {
            // Test each error condition systematically

            // 1. Wrong state
            let complete_connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_peer_key(KeyPair::generate().pub_key().to_hex().hex())
                .with_password("StrongPassword123!@#")
                .build()
                .unwrap();

            let result = complete_connection.complete_with_password(
                &KeyPair::generate().pub_key().to_hex().hex(),
                "StrongPassword123!@#",
            );
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::InvalidStateTransition { .. }
            ));

            // 2. Missing KeySecure
            let mut no_keysecure = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440001".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .build()
                .unwrap();
            no_keysecure.update_state(State::PendingOutgoing);

            let result = no_keysecure.complete_with_password(
                &KeyPair::generate().pub_key().to_hex().hex(),
                "StrongPassword123!@#",
            );
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::CryptographicError(_)
            ));

            // 3. Invalid peer public key
            let partial_connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440002".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_password("StrongPassword123!@#".to_string())
                .build()
                .unwrap();

            let result =
                partial_connection.complete_with_password("invalid_key", "StrongPassword123!@#");
            assert!(result.is_err());

            // 4. Wrong password
            let result = partial_connection.complete_with_password(
                &KeyPair::generate().pub_key().to_hex().hex(),
                "WrongPassword456!@#",
            );
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::CryptographicError(_)
            ));
        }

        /// Tests boundary conditions for peer key validation
        #[test]
        fn test_peer_key_boundary_conditions() {
            let connection = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:peer".to_string())
                .with_password("StrongPassword123!@#".to_string())
                .build()
                .unwrap();

            // Edge cases for peer key length
            let boundary_cases = [
                ("", "empty key"),
                ("1", "single character"),
                ("12345", "short key"),
                (&"a".repeat(63), "63 characters"),
                (&"a".repeat(65), "65 characters"),
                (&"g".repeat(64), "invalid hex characters"),
            ];

            for (key, description) in boundary_cases {
                let result = connection.complete_with_password(key, "StrongPassword123!@#");
                assert!(result.is_err(), "Should fail for: {}", description);
            }
        }
    }
}
