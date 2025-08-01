//! # Connection Module
//!
//! The `connection` module provides comprehensive abstractions for establishing and managing
//! secure, private peer-to-peer connections in the vessel identity system using ECDH key exchange
//! and encrypted communication channels.
//!
//! ## Overview
//!
//! This module implements a complete connection lifecycle management system that enables two
//! identity holders to establish secure, private communication channels. The system handles
//! initial handshakes, cryptographic key exchange, state management, and connection maintenance
//! with built-in security guarantees and privacy protections.
//!
//! ## Module Structure
//!
//! - [`types`] - Core data types, identifiers, and domain entities (ConnectionID, PeerKey, etc.)
//! - [`api`] - High-level API for connection operations (submit, approve, complete workflows)
//! - [`connection`] - Core connection entity with state machine and cryptographic materials
//! - [`notification`] - Approval notification system for handling peer responses
//!
//! ## Connection Workflow
//!
//! The module supports a comprehensive connection establishment workflow:
//!
//! ### 1. **Request Submission** (`request_submit`)
//! ```text
//! Alice wants to connect to Bob
//! ├── Alice creates connection request with password
//! ├── Generates ECDH key pair (public/private keys)
//! ├── Saves connection in PendingOutgoing state
//! └── Sends approval request to Bob via RPC
//! ```
//!
//! ### 2. **Request Response** (`request_response`)
//! ```text
//! Bob receives Alice's connection request
//! ├── Bob reviews the connection request
//! ├── Bob approves/rejects with password
//! ├── If approved: generates ECDH key pair
//! ├── Saves connection in Established state
//! └── Sends approval notification back to Alice
//! ```
//!
//! ### 3. **Approval Completion** (`request_complete_approval`)
//! ```text
//! Alice receives Bob's approval
//! ├── Alice retrieves approval notification
//! ├── Provides password to decrypt private key
//! ├── Completes ECDH key exchange with Bob's public key
//! ├── Generates shared secret
//! ├── Updates connection to Established state
//! └── Connection is ready for secure communication
//! ```
//!
//! ## Key Features
//!
//! ### **🔐 Cryptographic Security**
//! - **ECDH Key Exchange**: Elliptic Curve Diffie-Hellman for secure shared secret generation
//! - **Password-Based Encryption**: Private keys encrypted using user passwords with KeySecure
//! - **Forward Secrecy**: Each connection has unique cryptographic materials
//! - **Secure Key Storage**: All cryptographic materials are encrypted at rest
//!
//! ### **🔒 Privacy Protection**
//! - **Peer-to-Peer**: Direct communication without intermediary servers
//! - **No Metadata Leakage**: Connection details are not exposed to third parties
//! - **Identity Protection**: Peer identities are only revealed during explicit connection
//! - **Selective Disclosure**: Users control what information is shared during connection
//!
//! ### **🔄 State Management**
//! - **Connection States**: Clear state machine (PendingOutgoing → PendingIncoming → Established)
//! - **Atomic Operations**: All connection operations are atomic and consistent
//! - **Idempotency**: Safe retry mechanisms for network failures
//! - **Error Recovery**: Robust error handling with detailed context
//!
//! ### **📬 Notification System**
//! - **Approval Notifications**: Async notification system for connection approvals
//! - **User Alerts**: Integration with notification services for user awareness
//! - **Cleanup Management**: Automatic cleanup of processed notifications
//! - **Concurrent Safety**: Thread-safe notification processing
//!
//! ## Security Guarantees
//!
//! ### **Authentication**
//! - Peer identity verification through DID-based authentication
//! - Password-based access control for connection operations
//! - Cryptographic proof of identity possession
//!
//! ### **Confidentiality**
//! - All connection data encrypted with shared secrets
//! - Private keys never transmitted over network
//! - Password-derived encryption for key material protection
//!
//! ### **Integrity**
//! - Cryptographic signatures for all connection operations
//! - Tamper-evident storage of connection state
//! - Atomic state transitions prevent partial failures
//!
//! ## Usage Examples
//!
//! ### **Basic Connection Establishment**
//! ```rust
//! use vessel_core::identity::connection::api::{ConnectionAPI, ConnectionAPIImpl};
//! use vessel_core::identity::connection::types::{ConnectionID, PeerDIDURI};
//!
//! // Alice initiates connection to Bob
//! let api = ConnectionAPIImpl::new(repo, rpc, notification_repo, notification_service);
//! let peer_did = PeerDIDURI::new("did:example:bob".to_string())?;
//! let password = "SecurePassword123!".to_string();
//!
//! // Step 1: Alice submits connection request
//! api.request_submit(peer_did, password).await?;
//!
//! // Step 2: Bob responds to the request (on Bob's side)
//! let requests = api.request_incoming_requests().await?;
//! api.request_response(requests[0].get_id(), true, "BobPassword456!".to_string()).await?;
//!
//! // Step 3: Alice completes the connection (on Alice's side)
//! let notifications = api.request_notifications().await?;
//! api.request_complete_approval(notifications[0].get_id(), "SecurePassword123!".to_string()).await?;
//!
//! // Connection is now established and ready for secure communication
//! ```
//!
//! ### **Notification-Driven Workflow**
//! ```rust
//! // Check for pending approvals periodically
//! let notifications = api.request_notifications().await?;
//! for notification in notifications {
//!     println!("Approval ready from peer: {}", notification.get_peer_did());
//!     
//!     // User can choose to complete the connection
//!     let user_password = get_user_password();
//!     api.request_complete_approval(notification.get_id(), user_password).await?;
//! }
//! ```
//!
//! ## Integration Points
//!
//! ### **Repository Layer**
//! - Requires implementation of `RepoBuilder<EntityAccessor = Connection>`
//! - Notification storage via `NotificationRepoBuilder`
//! - Atomic transaction support for consistency
//!
//! ### **RPC Layer**
//! - Integration with `RpcBuilder` for peer communication
//! - Handles `request_approval` calls from remote peers
//! - Network failure resilience and retry logic
//!
//! ### **Notification Services**
//! - User notification via `NotificationService` trait
//! - Push notifications for approval events
//! - Real-time updates for connection status changes
//!
//! ## Error Handling
//!
//! The module provides comprehensive error handling through `ConnectionError`:
//!
//! - **ValidationError**: Input validation failures (invalid IDs, malformed data)
//! - **InvalidPassword**: Password complexity or authentication failures
//! - **InvalidConnectionID**: Connection lookup or reference failures
//! - **InvalidStateTransition**: Invalid state machine transitions
//! - **EntityError**: Repository and persistence failures
//! - **CryptographicError**: Key generation or ECDH operation failures
//! - **NotImplementedError**: Placeholder for unimplemented features
//!
//! ## Thread Safety
//!
//! All API methods are designed to be thread-safe when used with appropriate repository
//! and RPC implementations. Concurrent operations on different connections are fully
//! supported, while operations on the same connection are serialized for consistency.
//!
//! ## Performance Considerations
//!
//! - **Cryptographic Operations**: ECDH key generation may take several milliseconds
//! - **Database Operations**: Connection state changes require database persistence
//! - **Network Operations**: RPC calls to peers may have variable latency
//! - **Memory Usage**: Cryptographic materials are kept in memory during operations

pub mod api;
pub mod connection;
pub mod notification;
pub mod types;