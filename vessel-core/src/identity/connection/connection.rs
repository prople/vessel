//! # Connection Module
//!
//! This module provides secure peer-to-peer connection establishment using ECDH key agreement.
//! It implements a connection entity that stores peer information, cryptographic keys, and 
//! shared secrets for secure communication between decentralized identity participants.
//!
//! ## Key Features
//! - ECDH key agreement for secure shared secret generation
//! - KeySecure encryption for private key storage
//! - Comprehensive input validation (UUID, DID URI, hex keys, password complexity)
//! - Builder pattern for ergonomic connection creation
//! - JSON and binary serialization support
//! - State management for connection lifecycle
//!
//! ## Usage Example
//! ```rust
//! use prople_crypto::ecdh::keypair::KeyPair;
//! 
//! // Generate keypairs for Alice and Bob
//! let alice_keypair = KeyPair::generate();
//! let bob_keypair = KeyPair::generate();
//! 
//! // Alice creates connection to Bob
//! let alice_connection = Connection::builder()
//!     .with_id("550e8400-e29b-41d4-a716-446655440000")
//!     .with_peer_did_uri("did:example:bob")
//!     .with_peer_key(bob_keypair.pub_key().to_hex().hex())
//!     .with_password("StrongPassword123!@#")
//!     .with_own_keypair(alice_keypair)
//!     .build()?;
//! ```

use std::fmt::Debug;

use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::serde_json;
use rst_common::standard::uuid::Uuid;

use rstdev_domain::entity::ToJSON;
use rstdev_domain::BaseError;

use prople_crypto::keysecure::KeySecure;
use prople_crypto::keysecure::types::{Password, ToKeySecure};
use prople_crypto::ecdh::keypair::KeyPair;
use prople_crypto::types::{ByteHex, Hexer, VectorValue};

use super::types::{
    ConnectionContext, ConnectionEntityAccessor, ConnectionEntityOwn, ConnectionEntityPeer,
    ConnectionError, ConnectionID, OwnKey, OwnSharedSecret, PeerDIDURI, PeerKey, State,
};

/// # Connection Entity
/// 
/// Represents a secure connection between two decentralized identity peers using ECDH key agreement.
/// 
/// ## Security Features
/// - **ECDH Key Agreement**: Generates shared secrets using Elliptic Curve Diffie-Hellman
/// - **KeySecure Encryption**: Private keys are encrypted using password-derived keys
/// - **Blake3 Hashing**: Shared secrets are hashed using Blake3 for consistency
/// - **Input Validation**: Comprehensive validation of all inputs (UUIDs, DIDs, hex keys, passwords)
/// 
/// ## Connection Lifecycle
/// 1. **Pending**: Initial state when connection is created
/// 2. **Established**: State after successful peer handshake
/// 3. **Failed**: State when connection establishment fails
/// 
/// ## Data Storage
/// - All cryptographic material is stored securely
/// - Private keys are never stored in plaintext
/// - Shared secrets are Blake3-hashed for consistency
/// - Timestamps track creation and updates
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub struct Connection {
    /// Unique identifier for this connection (UUID v4 format)
    /// Used to track and reference this specific connection
    id: ConnectionID,
    
    /// Current state of the connection (Pending, Established, or Failed)
    /// Tracks the connection lifecycle for state machine management
    state: State,
    
    /// Context of the connection (currently only supports Connection type)
    /// Extensible for future connection types (e.g., Authentication, Authorization)
    context: ConnectionContext,
    
    /// DID URI of the peer we're connecting to
    /// Must follow W3C DID specification: did:method:identifier
    peer_did_uri: PeerDIDURI,
    
    /// Public key of the peer (hex encoded, 64 characters for X25519)
    /// Used in ECDH key agreement to generate shared secret
    peer_key: PeerKey,
    
    /// Connection ID from peer's perspective
    /// Allows bidirectional connection tracking
    peer_connection_id: ConnectionID,
    
    /// Our own public key (hex encoded)
    /// Generated from our private key, shared with peer for ECDH
    own_key: OwnKey,
    
    /// Our own private key stored securely using KeySecure format
    /// Encrypted with password-derived key, never stored in plaintext
    own_keysecure: KeySecure,
    
    /// Shared secret generated from ECDH key agreement (Blake3 hash, hex encoded)
    /// Result of ECDH(our_private_key, peer_public_key) -> Blake3 -> hex
    own_shared_secret: OwnSharedSecret,
    
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
    /// # Returns
    /// - `ConnectionBuilder`: A builder instance for constructing connections
    /// 
    /// # Example
    /// ```rust
    /// let connection = Connection::builder()
    ///     .with_id("550e8400-e29b-41d4-a716-446655440000")
    ///     .with_peer_did_uri("did:example:peer")
    ///     .build()?;
    /// ```
    pub fn builder() -> ConnectionBuilder {
        ConnectionBuilder::new()
    }
    
    /// Updates the connection state and refreshes the updated timestamp
    /// 
    /// This method is used to manage the connection lifecycle:
    /// - Pending -> Established (after successful handshake)
    /// - Pending -> Failed (if handshake fails)
    /// - Established -> Failed (if connection drops)
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
    fn get_own_key(&self) -> OwnKey {
        self.own_key.clone()
    }
    
    /// Returns our own private key in KeySecure format
    /// Private key is encrypted with password-derived key for security
    fn get_own_keysecure(&self) -> KeySecure {
        self.own_keysecure.clone()
    }
    
    /// Returns the shared secret generated from ECDH key agreement
    /// This is the Blake3 hash of ECDH(our_private, peer_public)
    fn get_own_shared_secret(&self) -> OwnSharedSecret {
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
        serde_json::to_string(self)
            .map_err(|e| BaseError::ToJSONError(e.to_string()))
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
        serde_json::to_vec(&self)
            .map_err(|e| ConnectionError::EntityError(e.to_string()))
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
        serde_json::from_slice(&bytes)
            .map_err(|e| ConnectionError::EntityError(e.to_string()))
    }
}

/// # Connection Builder
/// 
/// Provides a fluent API for constructing Connection objects with comprehensive validation.
/// 
/// ## Validation Features
/// - **UUID Validation**: Ensures connection IDs are valid UUID v4 format
/// - **DID URI Validation**: Validates W3C DID specification compliance
/// - **Hex Key Validation**: Ensures peer keys are valid 64-character hex strings
/// - **Password Complexity**: Enforces strong password requirements
/// 
/// ## Builder Pattern Benefits
/// - **Type Safety**: Compile-time verification of required fields
/// - **Ergonomic API**: Fluent method chaining for easy use
/// - **Comprehensive Validation**: All inputs validated before object creation
/// - **Flexible Construction**: Optional fields with sensible defaults
/// 
/// ## Required Fields
/// - `id`: Connection identifier (UUID format)
/// - `peer_did_uri`: Peer's DID URI (did:method:identifier format)
/// - `peer_key`: Peer's public key (64-character hex string)
/// - `password`: Password for KeySecure encryption (min 12 chars, complexity required)
/// 
/// ## Optional Fields
/// - `peer_connection_id`: Peer's connection ID (auto-generated if not provided)
/// - `context`: Connection context (defaults to Connection)
/// - `own_keypair`: Our keypair (auto-generated if not provided)
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
                "Password must be at least 12 characters long".to_string()
            ));
        }
        
        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));
        
        if !has_lowercase {
            return Err(ConnectionError::ValidationError(
                "Password must contain at least one lowercase letter".to_string()
            ));
        }
        
        if !has_uppercase {
            return Err(ConnectionError::ValidationError(
                "Password must contain at least one uppercase letter".to_string()
            ));
        }
        
        if !has_digit {
            return Err(ConnectionError::ValidationError(
                "Password must contain at least one digit".to_string()
            ));
        }
        
        if !has_special {
            return Err(ConnectionError::ValidationError(
                "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)".to_string()
            ));
        }
        
        Ok(())
    }

    /// Builds the Connection object with comprehensive validation and ECDH key generation
    /// 
    /// This method supports two build modes:
    /// 1. **Complete Connection**: When peer_key is provided, generates full ECDH shared secret
    /// 2. **Partial Connection**: When peer_key is missing, creates connection for outgoing requests
    /// 
    /// # Returns
    /// - `Ok(Connection)`: Successfully constructed and validated connection
    /// - `Err(ConnectionError)`: Validation or cryptographic error
    pub fn build(mut self) -> Result<Connection, ConnectionError> {
        // Step 1: Extract and validate required fields
        let id_str = self.id.take().ok_or_else(|| 
            ConnectionError::ValidationError("Connection ID is required".to_string()))?;
        
        ConnectionID::validate(id_str.as_ref())?;
        let id = ConnectionID::from_validated(id_str.as_ref().to_string());
        
        let peer_did_uri_str = self.peer_did_uri.take().ok_or_else(|| 
            ConnectionError::ValidationError("Peer DID URI is required".to_string()))?;
        
        PeerDIDURI::validate(peer_did_uri_str.as_ref())?;
        let peer_did_uri = PeerDIDURI::from_validated(peer_did_uri_str.as_ref().to_string());
        
        let password = self.password.take().ok_or_else(|| 
            ConnectionError::ValidationError("Password is required".to_string()))?;
        
        // Validate password complexity
        Self::validate_password(&password)?;
        
        // Step 2: Handle optional peer key
        let peer_key_option = self.peer_key.take();
        
        // Step 3: Set defaults for optional fields
        let peer_connection_id = self.peer_connection_id.clone()
            .unwrap_or_else(|| ConnectionID::from(Uuid::new_v4().to_string()));
        let context = self.context.clone().unwrap_or(ConnectionContext::Connection);
        
        // Step 4: Build based on whether we have peer key or not
        match peer_key_option {
            Some(peer_key_str) => {
                // Complete connection with ECDH shared secret
                PeerKey::validate(peer_key_str.as_ref())?;
                let peer_key = PeerKey::from_validated(peer_key_str.as_ref().to_string());
                Self::generate_complete_connection(id, peer_did_uri, peer_key, peer_connection_id, password, context, self.own_keypair)
            },
            None => {
                // Partial connection for outgoing requests (no peer key yet)
                Self::generate_partial_connection(id, peer_did_uri, peer_connection_id, password, context, self.own_keypair)
            }
        }
    }
    
    /// Generates a complete Connection with ECDH shared secret
    /// 
    /// Used when we have both our keypair and the peer's public key.
    /// This is the original implementation for complete connections.
    fn generate_complete_connection(
        id: ConnectionID,
        peer_did_uri: PeerDIDURI,
        peer_key: PeerKey,
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
        
        // ✅ Correct KeySecure encryption using ToKeySecure trait
        let password_obj = Password::from(password);
        let own_keysecure = keypair.to_keysecure(password_obj)
            .map_err(|e| ConnectionError::CryptographicError(
                format!("KeySecure encryption failed: {}", e)
            ))?;
        
        // Prepare peer's public key for ECDH computation
        let peer_key_clean = peer_key.as_ref()
            .strip_prefix("0x")
            .unwrap_or(peer_key.as_ref());
        
        let peer_key_hex = ByteHex::from(peer_key_clean.to_string());
        
        // Compute the ECDH shared secret: ECDH(our_private, peer_public)
        let secret = keypair.secret(peer_key_hex);
        
        // Hash the raw ECDH output using Blake3 for consistency
        let shared_secret = secret.to_blake3()
            .map_err(|e| ConnectionError::CryptographicError(
                format!("Shared secret generation failed: {}", e)
            ))?;
        
        let now = Utc::now();
        
        // Construct complete Connection object
        Ok(Connection {
            id,
            state: State::Pending,
            context,
            peer_did_uri,
            peer_key,
            peer_connection_id,
            own_key: OwnKey::from(own_key_hex.hex()),
            own_keysecure,
            own_shared_secret: OwnSharedSecret::from(shared_secret.hex()),
            created_at: now,
            updated_at: now,
        })
    }
    
    /// Generates a partial Connection for outgoing requests (without peer key)
    /// 
    /// Used when initiating connection requests where we don't have the peer's
    /// public key yet. The connection will be completed later when the peer responds.
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
        
        // ✅ Correct KeySecure encryption using ToKeySecure trait
        let password_obj = Password::from(password);
        let own_keysecure = keypair.to_keysecure(password_obj)
            .map_err(|e| ConnectionError::CryptographicError(
                format!("KeySecure encryption failed: {}", e)
            ))?;
        
        let now = Utc::now();
        
        // Construct partial Connection object with placeholder values
        Ok(Connection {
            id,
            state: State::PendingOutgoing, // ✅ New state for outgoing requests
            context,
            peer_did_uri,
            peer_key: PeerKey::from_validated("0000000000000000000000000000000000000000000000000000000000000000".to_string()),
            peer_connection_id,
            own_key: OwnKey::from(own_key_hex.hex()),
            own_keysecure,
            own_shared_secret: OwnSharedSecret::from("pending".to_string()),
            created_at: now,
            updated_at: now,
        })
    }
    
    /// Completes a partial connection when the peer's public key becomes available
    /// 
    /// This method is called when we receive the peer's public key (e.g., during approval).
    /// It computes the ECDH shared secret and updates the connection to established state.
    /// 
    /// # Parameters
    /// - `connection`: Mutable reference to the partial connection
    /// - `peer_key`: The peer's public key received from their response
    /// - `password`: Password to decrypt our private key
    /// 
    /// # Returns
    /// - `Ok(())`: Connection successfully completed
    /// - `Err(ConnectionError)`: Cryptographic operation failure
    pub fn complete_connection(
        connection: &mut Connection,
        peer_key: PeerKey,
        password: &str,
    ) -> Result<(), ConnectionError> {
        // Verify this is a partial connection
        if connection.state != State::PendingOutgoing {
            return Err(ConnectionError::ValidationError(
                "Can only complete connections in PendingOutgoing state".to_string()
            ));
        }
        
        // ✅ Decrypt the private key from KeySecure
        let decrypted_message = connection.own_keysecure.decrypt(password.to_string())
            .map_err(|e| ConnectionError::CryptographicError(
                format!("Failed to decrypt private key: {}", e)
            ))?;
        
        // ✅ Convert decrypted bytes back to hex string
        // KeySecure always stores private key as hex-encoded string
        let private_key_hex = String::from_utf8(decrypted_message.vec())
            .map_err(|e| ConnectionError::CryptographicError(
                format!("Failed to convert decrypted data to hex string: {}", e)
            ))?;
        
        // ✅ Reconstruct KeyPair from hex string (same as KeyPair::from_hex)
        let keypair = KeyPair::from_hex(private_key_hex)
            .map_err(|e| ConnectionError::CryptographicError(
                format!("Failed to reconstruct keypair from hex: {}", e)
            ))?;
        
        // Prepare peer's public key for ECDH computation
        let peer_key_clean = peer_key.as_ref()
            .strip_prefix("0x")
            .unwrap_or(peer_key.as_ref());
        let peer_key_hex = ByteHex::from(peer_key_clean.to_string());
        
        // Compute the ECDH shared secret
        let secret = keypair.secret(peer_key_hex);
        let shared_secret = secret.to_blake3()
            .map_err(|e| ConnectionError::CryptographicError(
                format!("Shared secret generation failed: {}", e)
            ))?;
        
        // Update connection with real peer data
        connection.peer_key = peer_key;
        connection.own_shared_secret = OwnSharedSecret::from(shared_secret.hex());
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
        
        assert!(connection.is_ok(), "Complete connection should be created successfully: {:?}", connection.err());
        let conn = connection.unwrap();
        assert_eq!(conn.get_state(), State::Pending); // Complete connections start in Pending
        assert_eq!(conn.get_context(), ConnectionContext::Connection);
        assert_ne!(conn.get_own_shared_secret().as_ref(), "pending"); // Should have real shared secret
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
        
        assert!(connection.is_ok(), "Partial connection should be created successfully: {:?}", connection.err());
        let conn = connection.unwrap();
        
        // Verify partial connection properties
        assert_eq!(conn.get_state(), State::PendingOutgoing); // ✅ New state for partial connections
        assert_eq!(conn.get_peer_key().as_ref(), "0000000000000000000000000000000000000000000000000000000000000000"); // Placeholder
        assert_eq!(conn.get_own_shared_secret().as_ref(), "pending"); // Placeholder
        assert_ne!(conn.get_own_key().as_ref(), ""); // Should have our real public key
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
        assert_eq!(connection.get_own_key().as_ref(), &expected_pub_key);
        
        // Verify placeholder values
        assert_eq!(connection.get_peer_key().as_ref(), "0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(connection.get_own_shared_secret().as_ref(), "pending");
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
            "StrongPassword123!@#"
        );
        
        assert!(result.is_ok(), "Connection completion should succeed: {:?}", result.err());
        
        // Step 3: Verify completion results
        assert_eq!(connection.get_state(), State::Established); // ✅ Should be established now
        assert_eq!(connection.get_peer_key(), peer_public_key); // ✅ Should have real peer key
        assert_ne!(connection.get_own_shared_secret().as_ref(), "pending"); // ✅ Should have real shared secret
        
        // Step 4: Verify ECDH correctness by computing expected shared secret
        let peer_key_clean = peer_public_key.as_ref().strip_prefix("0x").unwrap_or(peer_public_key.as_ref());
        let peer_key_hex = ByteHex::from(peer_key_clean.to_string());
        let expected_secret = our_keypair.secret(peer_key_hex).to_blake3().unwrap();
        
        assert_eq!(connection.get_own_shared_secret().as_ref(), &expected_secret.hex());
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
            "StrongPassword123!@#"
        );
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectionError::ValidationError(_)));
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
            "WrongPassword456!@#" // ❌ Wrong password
        );
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectionError::CryptographicError(_)));
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
        assert!(matches!(result.unwrap_err(), ConnectionError::ValidationError(_)));
        
        // Missing peer DID URI
        let result = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_password("StrongPassword123!@#".to_string())
            .build();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectionError::ValidationError(_)));
        
        // Missing password
        let result = Connection::builder()
            .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
            .with_peer_did_uri("did:example:test".to_string())
            .build();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConnectionError::ValidationError(_)));
    }
    
    /// Tests rejection of invalid peer key formats (when provided)
    #[test]
    fn test_invalid_peer_key_formats() {
        let invalid_keys = [
            "short",                           // Too short
            "not_hex_characters",             // Non-hex chars
            "",                               // Empty
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
            assert!(matches!(result.unwrap_err(), ConnectionError::ValidationError(_)));
        }
    }
    
    /// Tests rejection of weak passwords
    #[test]
    fn test_weak_password_validation() {
        let weak_passwords = [
            "",                    // Empty
            "short",              // Too short
            "onlylowercase",      // Missing requirements
            "ONLYUPPERCASE",      // Missing requirements  
            "NoNumbers!@#",       // Missing numbers
            "NoSpecialChars123",  // Missing special chars
            "nouppercase123!",    // Missing uppercase
            "NOLOWERCASE123!",    // Missing lowercase
        ];
        
        for weak_password in weak_passwords {
            let result = Connection::builder()
                .with_id("550e8400-e29b-41d4-a716-446655440000".to_string())
                .with_peer_did_uri("did:example:test".to_string())
                .with_password(weak_password.to_string())
                .build();
            
            assert!(result.is_err(), "Should fail for password: '{}'", weak_password);
            assert!(matches!(result.unwrap_err(), ConnectionError::ValidationError(_)));
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
        assert!(!shared_secret.as_ref().is_empty());
        assert_eq!(shared_secret.as_ref().len(), 64); // Blake3 = 32 bytes = 64 hex chars
        assert!(shared_secret.as_ref().chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(shared_secret.as_ref(), "pending"); // Should not be placeholder
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
        let bytes: Vec<u8> = connection.clone().try_into().expect("Should serialize to bytes");
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
        assert!(json.contains("0000000000000000000000000000000000000000000000000000000000000000")); // Placeholder peer key
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
        assert_eq!(conn.get_peer_connection_id().as_ref(), "550e8400-e29b-41d4-a716-446655440001");
        assert_eq!(conn.get_own_key().as_ref(), &own_keypair.pub_key().to_hex().hex());
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
}