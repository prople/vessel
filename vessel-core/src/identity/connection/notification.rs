use derive_more::{AsRef, From, Into};
use the_newtype::Newtype;

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::uuid::Uuid;

use super::types::{ConnectionError, ConnectionID, PeerDIDURI, PeerKey};

/// Unique identifier for approval notifications
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Newtype, From, Into, AsRef)]
#[serde(crate = "self::serde")]
pub struct NotificationID(String);

impl NotificationID {
    /// Generate a new unique notification ID
    pub fn generate() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from validated string
    pub fn from_validated(id: String) -> Self {
        Self(id)
    }

    /// Get the inner string reference
    pub fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Repository abstraction for managing approval notifications.
///
/// This trait provides persistence operations for approval notifications,
/// allowing different storage backends (database, in-memory, file-based, etc.)
/// to be used interchangeably.
#[async_trait]
pub trait NotificationRepoBuilder: Clone + Send + Sync {
    /// Save a new approval notification to storage
    ///
    /// # Arguments
    /// * `notification` - The notification to save
    ///
    /// # Returns
    /// * `Ok(())` - Notification saved successfully
    /// * `Err(ConnectionError)` - Error occurred during save operation
    async fn save_notification(
        &self,
        notification: &ApprovalNotification,
    ) -> Result<(), ConnectionError>;

    /// Retrieve all pending notifications from storage
    ///
    /// # Returns
    /// * `Ok(Vec<ApprovalNotification>)` - List of all pending notifications
    /// * `Err(ConnectionError)` - Error occurred during retrieval
    async fn list_notifications(&self) -> Result<Vec<ApprovalNotification>, ConnectionError>;

    /// Retrieve a specific notification by ID
    ///
    /// # Arguments
    /// * `id` - Unique identifier of the notification
    ///
    /// # Returns
    /// * `Ok(ApprovalNotification)` - The requested notification
    /// * `Err(ConnectionError)` - Notification not found or other error
    async fn get_notification(
        &self,
        id: NotificationID,
    ) -> Result<ApprovalNotification, ConnectionError>;

    /// Remove a notification from storage after completion/dismissal
    ///
    /// # Arguments
    /// * `id` - Unique identifier of the notification to remove
    ///
    /// # Returns
    /// * `Ok(())` - Notification removed successfully
    /// * `Err(ConnectionError)` - Error occurred during removal
    async fn remove_notification(&self, id: NotificationID) -> Result<(), ConnectionError>;
}

/// Service abstraction for notifying users of pending approvals.
///
/// This trait abstracts the mechanism used to notify users when approval
/// notifications are received. Implementations can use push notifications,
/// webhooks, email, UI callbacks, etc.
#[async_trait]
pub trait NotificationService: Clone + Send + Sync {
    /// Notify user of a new approval notification
    ///
    /// This method is called when a peer approves a connection request.
    /// The implementation should notify the user through appropriate channels
    /// (push notification, UI update, webhook, etc.)
    ///
    /// # Arguments
    /// * `notification` - The approval notification to present to the user
    ///
    /// # Returns
    /// * `Ok(())` - User successfully notified
    /// * `Err(ConnectionError)` - Error occurred during notification
    async fn notify_approval_received(
        &self,
        notification: &ApprovalNotification,
    ) -> Result<(), ConnectionError>;

    /// Optional: Notify user when an approval is completed
    ///
    /// # Arguments
    /// * `connection_id` - ID of the connection that was completed
    ///
    /// # Returns
    /// * `Ok(())` - User successfully notified
    /// * `Err(ConnectionError)` - Error occurred during notification
    async fn notify_approval_completed(
        &self,
        connection_id: ConnectionID,
    ) -> Result<(), ConnectionError>;
}

/// Represents a pending connection approval notification
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalNotification {
    /// Unique identifier for this notification
    id: NotificationID,
    /// Our connection ID that needs completion
    connection_id: ConnectionID,
    /// Peer's public key for ECDH completion
    peer_public_key: PeerKey,
    /// Timestamp when approval was received
    received_at: DateTime<Utc>,
    /// Peer information for display purposes
    peer_did_uri: PeerDIDURI,
}

impl ApprovalNotification {
    /// Create a new approval notification
    pub fn new(
        connection_id: ConnectionID,
        peer_public_key: PeerKey,
        peer_did_uri: PeerDIDURI,
    ) -> Self {
        Self {
            id: NotificationID::generate(),
            connection_id,
            peer_public_key,
            received_at: Utc::now(),
            peer_did_uri,
        }
    }

    /// Create with specific ID (for testing/reconstruction)
    pub fn with_id(
        id: NotificationID,
        connection_id: ConnectionID,
        peer_public_key: PeerKey,
        peer_did_uri: PeerDIDURI,
        received_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            connection_id,
            peer_public_key,
            received_at,
            peer_did_uri,
        }
    }

    // Getters
    pub fn get_id(&self) -> &NotificationID {
        &self.id
    }
    pub fn get_connection_id(&self) -> &ConnectionID {
        &self.connection_id
    }
    pub fn get_peer_public_key(&self) -> &PeerKey {
        &self.peer_public_key
    }
    pub fn get_received_at(&self) -> &DateTime<Utc> {
        &self.received_at
    }
    pub fn get_peer_did_uri(&self) -> &PeerDIDURI {
        &self.peer_did_uri
    }
}
