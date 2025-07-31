use super::connection::Connection;
use super::types::*;
use rst_common::standard::async_trait::async_trait;

/// ConnectionAPIImpl is the concrete implementation of the Connection API that manages
/// peer-to-peer connection requests and lifecycle.
///
/// This implementation uses a composition pattern combining:
/// - Repository abstraction for data persistence
/// - RPC client for peer communication
/// - Connection entity for secure connection data access
///
/// ## Connection Lifecycle
///
/// The connection process follows this flow:
/// 1. **Pending State**: Connection request is submitted and stored locally
/// 2. **Peer Communication**: Request is sent to target peer via RPC
/// 3. **Response Handling**: Peer approves/rejects the connection
/// 4. **Established State**: Successful connections generate shared secrets via ECDH
///
/// ## Dual Perspectives
///
/// The API handles two perspectives:
/// - **Sender**: Entity that initiates connection requests (`request_submit`, `request_submissions`)
/// - **Peer**: Entity that receives and responds to requests (`request_list`, `request_response`)
///
/// ## Security Model
///
/// - Each connection generates new ECDH keypairs
/// - Private keys are stored securely using `KeySecure`
///
/// - Shared secrets are generated only after successful approval
/// - All cryptographic operations are handled through the Connection entity
///
/// ## Generic Parameters
///
/// - `TRepo`: Repository implementation for data persistence
/// - `TRPC`: RPC client implementation for peer communication
///
/// ## Thread Safety
///
/// All generic parameters require `Send + Sync` bounds to ensure safe usage
/// across thread boundaries in async contexts.
///
/// ## Example Usage
///
/// ```rust
/// let repo = MyConnectionRepo::new();
/// let rpc = MyRpcClient::new();
/// let api = ConnectionAPIImpl::new(repo, rpc);
///
/// // Submit a new connection request
/// api.request_submit("password123".to_string(), peer_did, own_did).await?;
///
/// // List received connection requests
/// let requests = api.request_list().await?;
/// ```
#[derive(Clone)]
pub struct ConnectionAPIImpl<TRepo, TRPC>
where
    TRepo: RepoBuilder<EntityAccessor = Connection> + Send + Sync,
    TRPC: RpcBuilder + Send + Sync,
{
    /// Repository instance for connection data persistence
    repo: TRepo,
    /// RPC client for peer-to-peer communication
    rpc: TRPC,
}

impl<TRepo, TRPC> ConnectionAPIImpl<TRepo, TRPC>
where
    TRepo: RepoBuilder<EntityAccessor = Connection> + Send + Sync,
    TRPC: RpcBuilder + Send + Sync,
{
    /// Creates a new ConnectionAPIImpl instance.
    ///
    /// # Arguments
    ///
    /// * `repo` - Repository implementation that handles connection data persistence
    /// * `rpc` - RPC client implementation that handles peer communication
    ///
    /// # Returns
    ///
    /// A new ConnectionAPIImpl instance ready for use
    ///
    /// # Example
    ///
    /// ```rust
    /// let repo = MyConnectionRepo::new();
    /// let rpc = MyRpcClient::new();
    /// let api = ConnectionAPIImpl::new(repo, rpc);
    /// ```
    pub fn new(repo: TRepo, rpc: TRPC) -> Self {
        Self { repo, rpc }
    }
}

/// Implementation of the ConnectionAPI trait.
///
/// This provides the core connection management functionality including:
/// - Connection request lifecycle management
/// - Peer communication via RPC
/// - State transitions and data persistence
/// - Cryptographic key management through Connection entities
///
/// ## Method Categories
///
/// ### Remote Operations (Local + RPC)
/// - `request_submit`: Submit new connection request (local save + remote call)
/// - `request_cancel`: Cancel connection request (local remove + remote notification)
///
/// ### Remote-Triggered Operations (From RPC)
/// - `request_connect`: Handle incoming connection request from peer
/// - `request_approval`: Handle connection approval notification from peer
///
/// ### Local Operations (Repository Only)
/// - `request_submissions`: Get connection requests sent by this entity
/// - `request_list`: Get connection requests received by this entity
/// - `request_remove`: Remove connection request from local storage
///
/// ### State Management
/// - `request_response`: Respond to connection request with approval/rejection
///
/// ## Current Implementation Status
///
/// Most methods currently return `ConnectionError::NotImplementedError` except for
/// `request_submit` which is fully implemented.
#[async_trait]
impl<TRepo, TRPC> ConnectionAPI for ConnectionAPIImpl<TRepo, TRPC>
where
    TRepo: RepoBuilder<EntityAccessor = Connection> + Send + Sync,
    TRPC: RpcBuilder + Send + Sync,
{
    type EntityAccessor = Connection;

    /// Handles incoming connection requests from remote peers.
    ///
    /// This method is called when a peer sends a connection request via RPC.
    /// It stores the incoming request in pending state. No cryptographic material
    /// (keypair, KeySecure, shared secret) is generated until the request is approved.
    ///
    /// # Arguments
    /// * `connection_id` - Unique identifier for this connection request
    /// * `sender_did_uri` - DID URI of the requesting peer
    /// * `sender_public_key` - Public key from the peer for ECDH key exchange
    ///
    /// # Returns
    /// * `Ok(())` - Connection request successfully received and stored
    /// * `Err(ConnectionError)` - Error occurred during request processing
    async fn request_connect(
        &self,
        connection_id: ConnectionID,
        sender_did_uri: PeerDIDURI,
        sender_public_key: PeerKey,
    ) -> Result<(), ConnectionError> {
        // Step 1: Validate all inputs
        ConnectionID::validate(connection_id.as_ref())?;
        PeerDIDURI::validate(sender_did_uri.as_ref())?;
        PeerKey::validate(sender_public_key.as_ref())?;
        
        let own_connection_id = ConnectionID::generate();

        // Step 2: Build passwordless incoming connection (no password, no keypair)
        let connection = Connection::builder()
            .with_id(own_connection_id)
            .with_peer_connection_id(connection_id.as_ref().to_string())
            .with_peer_did_uri(sender_did_uri.as_ref().to_string())
            .with_peer_key(sender_public_key.as_ref().to_string())
            // No password, no own_keypair
            .build()
            .map_err(|e| match e {
                ConnectionError::ValidationError(_) => e,
                ConnectionError::CryptographicError(_) => e,
                _ => ConnectionError::CryptographicError(format!(
                    "Connection creation failed: {}",
                    e
                )),
            })?;

        // Step 3: Save to repository in PendingIncoming state
        self.repo.save(&connection).await.map_err(|e| {
            ConnectionError::EntityError(format!("Failed to save incoming connection: {}", e))
        })?;

        Ok(())
    }

    /// Handles connection approval notifications from remote peers.
    ///
    /// This method is called when a peer approves a connection request that
    /// was previously sent. It should update the connection state to established
    /// and generate the shared secret.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Unique identifier for the connection
    /// * `approver_did_uri` - DID URI of the peer who approved the connection
    /// * `peer_public_key` - Public key from the peer for shared secret generation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Connection successfully established
    /// * `Err(ConnectionError)` - Error occurred during approval processing
    ///
    /// # Implementation Notes
    ///
    /// Future implementation should:
    /// 1. Locate the pending connection request
    /// 2. Generate shared secret using ECDH
    /// 3. Update connection state to established
    /// 4. Store shared secret securely
    async fn request_approval(
        &self,
        _connection_id: ConnectionID,
        _approver_did_uri: PeerDIDURI,
        _peer_public_key: PeerKey,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    /// Responds to a connection request with approval or rejection.
    ///
    /// This method allows the receiving peer to approve or reject an incoming
    /// connection request. On approval, it generates shared secrets and notifies
    /// the requesting peer.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Unique identifier for the connection request
    /// * `approval` - Whether to approve or reject the connection
    /// * `password` - Optional password for additional security verification
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Response sent successfully
    /// * `Err(ConnectionError)` - Error occurred during response processing
    ///
    /// # Implementation Notes
    ///
    /// Future implementation should:
    /// 1. Validate the connection request exists and is pending
    /// 2. If approved: generate shared secret, update state, call request_approval via RPC
    /// 3. If rejected: remove connection request, notify peer
    /// 4. Handle password verification if provided
    async fn request_response(
        &self,
        _connection_id: ConnectionID,
        _approval: Approval,
        _password: Option<String>,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    /// Cancels a previously submitted connection request (sender perspective).
    ///
    /// This method performs the following steps:
    /// 1. Fetches the connection entity using the peer's connection ID.
    /// 2. Notifies the peer to remove the connection via RPC (`request_remove`).
    /// 3. Removes the connection entity from local storage.
    ///
    /// # State Transition
    /// - Connection is deleted from local storage; peer is notified to do the same.
    ///
    /// # Security
    /// - All cryptographic materials associated with the connection are securely deleted.
    ///
    /// # Errors
    /// - Returns `InvalidConnectionID` if the connection is not found.
    /// - Returns `EntityError` for repository or RPC failures.
    async fn request_cancel(&self, connection_id: ConnectionID) -> Result<(), ConnectionError> {
        // Step 1: Fetch the connection entity
        let connection = match self.repo.get_connection_by_peer_conn_id(connection_id.clone()).await {
            Ok(conn) => conn,
            Err(ConnectionError::InvalidConnectionID(_)) | Err(ConnectionError::ConnectionNotFound(_)) => {
                return Err(ConnectionError::InvalidConnectionID(format!("Connection not found: {}", connection_id)));
            }
            Err(e) => return Err(e),
        };

        // Step 2: Notify peer via RPC using peer_did_uri
        let peer_did_uri = connection.get_peer_did_uri();
        self.rpc.request_remove(connection_id.clone(), peer_did_uri.clone()).await.map_err(|e| {
            ConnectionError::EntityError(format!("Failed to notify peer: {}", e))
        })?;

        // Step 3: Remove the connection entity from the repository
        self.repo.remove(connection_id).await.map_err(|e| {
            ConnectionError::EntityError(format!("Failed to remove connection: {}", e))
        })?;

        Ok(())
    }

    /// Removes a connection request from local storage.
    ///
    /// This method is typically called via RPC when a peer cancels their
    /// connection request, or locally when a user wishes to delete a pending or failed request.
    /// It ensures the connection exists before attempting removal, and returns a clear error if not.
    ///
    /// # Arguments
    ///
    /// * `connection_id` - Unique identifier for the connection request to remove
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Connection request removed successfully
    /// * `Err(ConnectionError)` - Error occurred during removal (not found, repository failure, etc.)
    ///
    /// # Implementation Details
    ///
    /// 1. Checks if the connection exists in the repository.
    /// 2. If found, removes it from persistent storage.
    /// 3. If not found, returns a `ConnectionError::InvalidConnectionID`.
    /// 4. Any repository errors are wrapped in `ConnectionError::EntityError`.
    ///
    /// # Security
    ///
    /// All cryptographic materials associated with the connection are deleted as part of entity removal.
    /// No additional cleanup is required.
    async fn request_remove(&self, connection_id: ConnectionID) -> Result<(), ConnectionError> {
        // Step 1: Try to fetch the connection to ensure it exists
        match self.repo.get_connection_by_peer_conn_id(connection_id.clone()).await {
            Ok(_) => {
                // Step 2: Remove from repository
                self.repo.remove(connection_id).await.map_err(|e| {
                    ConnectionError::EntityError(format!("Failed to remove connection: {}", e))
                })
            }
            Err(ConnectionError::EntityError(_)) | Err(ConnectionError::InvalidConnectionID(_)) => {
                Err(ConnectionError::InvalidConnectionID(format!(
                    "Connection not found: {}",
                    connection_id
                )))
            }
            Err(e) => Err(e),
        }
    }

    /// Submits a new connection request to a remote peer.
    ///
    /// This method initiates a new connection request by generating cryptographic
    /// materials, storing the request locally, and sending it to the target peer.
    ///
    /// # Arguments
    ///
    /// * `password` - Password for encrypting the private key via KeySecure
    /// * `peer_did_uri` - DID URI of the target peer who will receive the request
    /// * `own_did_uri` - DID URI of the sender (us) for proper identity context
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Connection request submitted successfully
    /// * `Err(ConnectionError)` - Error occurred during submission
    ///
    /// # Implementation Details
    ///
    /// This implementation follows a local-first approach with automatic rollback:
    /// 1. Generates unique connection ID via UUID v4
    /// 2. Creates partial Connection entity with ECDH keypair generation
    /// 3. Validates password complexity and encrypts private key via KeySecure
    /// 4. Saves Connection directly to repository in PendingOutgoing state
    /// 5. Extracts public key and notifies peer via RPC
    /// 6. Implements automatic rollback if RPC fails
    ///
    /// # Security Considerations
    ///
    /// - DID URI validation enforced at API boundary via type system
    /// - Password complexity validation enforced by Connection::builder()
    /// - ECDH keypair generated with cryptographically secure randomness
    /// - Private keys encrypted with KeySecure before storage
    /// - Partial connection uses placeholder values until peer responds
    /// - Local-first approach ensures state consistency
    /// - Automatic rollback prevents orphaned connections
    async fn request_submit(
        &self,
        password: String,
        peer_did_uri: PeerDIDURI,
        own_did_uri: PeerDIDURI,
    ) -> Result<(), ConnectionError> {
        // Step 0: Validate that peer and own DIDs are different (PREVENT SELF-CONNECTIONS)
        if peer_did_uri.as_ref() == own_did_uri.as_ref() {
            return Err(ConnectionError::ValidationError(
                "Cannot create connection to self: peer_did_uri and own_did_uri must be different"
                    .to_string(),
            ));
        }

        // Step 1: Generate unique connection ID for this request
        let connection_id = ConnectionID::generate();

        // Step 2: Create partial connection entity using builder pattern
        // Omitting .with_peer_key() creates partial connection with placeholders
        let connection = Connection::builder()
            .with_id(connection_id.as_ref().to_string())
            .with_peer_did_uri(peer_did_uri.as_ref().to_string())
            .with_password(password)
            // Note: No .with_peer_key() call creates partial connection automatically
            .build()
            .map_err(|e| match e {
                ConnectionError::ValidationError(_) => e,
                ConnectionError::CryptographicError(_) => e,
                _ => ConnectionError::CryptographicError(format!(
                    "Connection creation failed: {}",
                    e
                )),
            })?;

        // Step 3: Save Connection entity directly to repository before network operations
        // Local-first approach ensures we have established state before RPC
        self.repo.save(&connection).await.map_err(|e| {
            ConnectionError::EntityError(format!("Failed to save connection: {}", e))
        })?;

        // Step 4: Extract our public key for transmission to peer
        let our_public_key = PeerKey::new(
            connection
                .get_own_key()
                .ok_or_else(|| {
                    ConnectionError::ValidationError("Missing own public key".to_string())
                })?
                .as_ref()
                .to_string(),
        )
        .map_err(|e| ConnectionError::ValidationError(format!("Invalid own public key: {}", e)))?;

        // Step 5: Notify peer via RPC with complete identity context
        // Implement automatic rollback pattern on network failure
        match self
            .rpc
            .request_connect(
                connection_id.clone(),
                own_did_uri,
                peer_did_uri,
                our_public_key,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(rpc_error) => {
                // Automatic rollback: remove saved connection on RPC failure
                // Ignore rollback errors to preserve original RPC error
                let _ = self.repo.remove(connection_id).await;
                Err(rpc_error)
            }
        }
    }

    /// Retrieves connection requests submitted by this entity.
    ///
    /// Returns all connection requests that were sent by this entity to other peers,
    /// regardless of their current state.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Connection>)` - List of submitted connection requests
    /// * `Err(ConnectionError)` - Error occurred during retrieval
    ///
    /// # Implementation Details
    ///
    /// - Queries the repository for connections in `PendingOutgoing` and `Established` states.
    /// - Returns the full list of matching connections.
    /// - Errors are wrapped in `ConnectionError::EntityError`.
    async fn request_submissions(&self) -> Result<Vec<Self::EntityAccessor>, ConnectionError> {
        // Outgoing states: PendingOutgoing, Established
        let outgoing_states = vec![State::PendingOutgoing, State::Established];
        self.repo
            .list_connections(Some(outgoing_states))
            .await
            .map_err(|e| ConnectionError::EntityError(format!("Failed to list submissions: {}", e)))
    }

    /// Retrieves connection requests received by this entity.
    ///
    /// Returns all connection requests that were received from other peers,
    /// regardless of their current state.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<Connection>)` - List of received connection requests
    /// * `Err(ConnectionError)` - Error occurred during retrieval
    ///
    /// # Implementation Details
    ///
    /// - Queries the repository for connections in `PendingIncoming` and `Established` states.
    /// - Returns the full list of matching connections.
    /// - Errors are wrapped in `ConnectionError::EntityError`.
    async fn request_list(&self) -> Result<Vec<Self::EntityAccessor>, ConnectionError> {
        // Incoming states: PendingIncoming, Established
        let incoming_states = vec![State::PendingIncoming, State::Established];
        self.repo
            .list_connections(Some(incoming_states))
            .await
            .map_err(|e| {
                ConnectionError::EntityError(format!("Failed to list received requests: {}", e))
            })
    }
}

/// Implementation of the ConnectionAPIImplBuilder trait.
///
/// This trait provides access to the underlying dependencies (repository and RPC client)
/// that compose this ConnectionAPIImpl. This is useful for:
///
/// - Testing scenarios where direct access to dependencies is needed
/// - Advanced use cases that require bypassing the main API
/// - Dependency injection and configuration scenarios
/// - Integration with other components that need direct repository/RPC access
///
/// # Design Pattern
///
/// This follows the builder pattern by exposing the internal components
/// while maintaining encapsulation of the main API functionality.
impl<TRepo, TRPC> ConnectionAPIImplBuilder<Connection> for ConnectionAPIImpl<TRepo, TRPC>
where
    TRepo: RepoBuilder<EntityAccessor = Connection> + Send + Sync,
    TRPC: RpcBuilder + Send + Sync,
{
    type Repo = TRepo;
    type RPCImplementer = TRPC;

    /// Returns a clone of the repository instance.
    ///
    /// This provides access to the underlying repository for direct
    /// data operations that may not be covered by the main API.
    ///
    /// # Returns
    ///
    /// A cloned instance of the repository
    fn repo(&self) -> Self::Repo {
        self.repo.clone()
    }

    /// Returns a clone of the RPC client instance.
    ///
    /// This provides access to the underlying RPC client for direct
    /// peer communication that may not be covered by the main API.
    ///
    /// # Returns
    ///
    /// A cloned instance of the RPC client
    fn rpc(&self) -> Self::RPCImplementer {
        self.rpc.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use rst_common::with_tokio::tokio;

    // ========================================
    // SHARED MOCK DEFINITIONS (GLOBAL)
    // ========================================

    mock!(
        FakeRepo{}

        impl Clone for FakeRepo {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RepoBuilder for FakeRepo {
            type EntityAccessor = Connection;

            async fn save(&self, connection: &Connection) -> Result<(), ConnectionError>;
            async fn remove(&self, id: ConnectionID) -> Result<(), ConnectionError>;
            async fn update_state(&self, id: ConnectionID, state: State) -> Result<(), ConnectionError>;
            async fn get_connection(&self, id: ConnectionID) -> Result<Connection, ConnectionError>;
            async fn list_connections(&self, state: Option<Vec<State>>) -> Result<Vec<Connection>, ConnectionError>;
            async fn get_connection_by_peer_conn_id(
                &self,
                peer_connection_id: ConnectionID,
            ) -> Result<Connection, ConnectionError>;
        }
    );

    mock!(
        FakeRPCClient{}

        impl Clone for FakeRPCClient {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl RpcBuilder for FakeRPCClient {
            async fn request_connect(&self, connection_id: ConnectionID, sender_did_uri: PeerDIDURI, receiver_did_uri: PeerDIDURI, sender_public_key: PeerKey) -> Result<(), ConnectionError>;
            async fn request_approval(&self, connection_id: ConnectionID, approver_did_uri: PeerDIDURI, approver_public_key: PeerKey) -> Result<(), ConnectionError>;
            async fn request_remove(&self, connection_id: ConnectionID, peer_did_uri: PeerDIDURI) -> Result<(), ConnectionError>;
        }
    );

    // ========================================
    // SHARED TEST UTILITIES (YOUR APPROACH)
    // ========================================

    fn generate_connection_api<
        TRepo: RepoBuilder<EntityAccessor = Connection> + Send + Sync,
        TRPCClient: RpcBuilder + Send + Sync,
    >(
        repo: TRepo,
        rpc: TRPCClient,
    ) -> ConnectionAPIImpl<TRepo, TRPCClient> {
        ConnectionAPIImpl::new(repo, rpc)
    }

    fn create_valid_test_data() -> (String, PeerDIDURI, PeerDIDURI) {
        let password = "StrongPassword123!@#".to_string();
        let peer_did = PeerDIDURI::new("did:example:123456789abcdefghi".to_string()).unwrap();
        let own_did = PeerDIDURI::new("did:example:987654321ihgfedcba".to_string()).unwrap();
        (password, peer_did, own_did)
    }

    // ========================================
    // ONE MODULE PER TRAIT METHOD
    // ========================================

    /// Tests for `request_submit` method
    mod request_submit_tests {
        use super::*;

        #[tokio::test]
        async fn test_request_submit_success() {
            // The repo will be used directly (not cloned) for save operation
            let mut repo = MockFakeRepo::new();
            repo.expect_save().times(1).returning(|_| Ok(()));

            // The rpc will be used directly (not cloned) for request_connect operation
            let mut rpc = MockFakeRPCClient::new();
            rpc.expect_request_connect()
                .times(1)
                .withf(|connection_id: &ConnectionID, sender_did: &PeerDIDURI, receiver_did: &PeerDIDURI, sender_key: &PeerKey| {
                    // Validate parameters
                    !connection_id.as_ref().is_empty() &&
                    sender_did.as_ref() == "did:example:987654321ihgfedcba" &&
                    receiver_did.as_ref() == "did:example:123456789abcdefghi" &&
                    sender_key.as_ref().len() == 64 &&
                    sender_key.as_ref() != "0000000000000000000000000000000000000000000000000000000000000000"
                })
                .returning(|_, _, _, _| Ok(()));

            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submit(password, peer_did, own_did).await;
            assert!(
                result.is_ok(),
                "Request submission should succeed: {:?}",
                result.err()
            );
        }

        #[tokio::test]
        async fn test_request_submit_weak_password_validation() {
            let repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();
            let (_, peer_did, own_did) = create_valid_test_data();

            let api = generate_connection_api(repo, rpc);

            let weak_passwords = [
                "",                  // Empty
                "short",             // Too short
                "onlylowercase",     // Missing requirements
                "ONLYUPPERCASE",     // Missing requirements
                "NoNumbers!@#",      // Missing numbers
                "NoSpecialChars123", // Missing special chars
            ];

            for weak_password in weak_passwords {
                let result = api
                    .request_submit(weak_password.to_string(), peer_did.clone(), own_did.clone())
                    .await;

                // Both error type matching AND message validation
                assert!(
                    result.is_err(),
                    "Should fail for weak password: '{}'",
                    weak_password
                );
                assert!(matches!(
                    result.unwrap_err(),
                    ConnectionError::ValidationError(_)
                ));
            }
        }

        #[tokio::test]
        async fn test_request_submit_repo_save_failure() {
            let mut repo = MockFakeRepo::new();
            repo.expect_save().times(1).returning(|_| {
                Err(ConnectionError::EntityError(
                    "Mock repository save failure".to_string(),
                ))
            });

            let rpc = MockFakeRPCClient::new();
            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submit(password, peer_did, own_did).await;

            // Error type matching
            assert!(result.is_err());
            assert!(matches!(
                result.as_ref().unwrap_err(),
                ConnectionError::EntityError(_)
            ));

            // Error message validation
            if let Err(ConnectionError::EntityError(msg)) = result {
                assert!(msg.contains("Failed to save connection"));
                assert!(msg.contains("Mock repository save failure"));
            }
        }

        #[tokio::test]
        async fn test_request_submit_rpc_failure_with_rollback() {
            let mut repo = MockFakeRepo::new();
            repo.expect_save().times(1).returning(|_| Ok(()));
            repo.expect_remove().times(1).returning(|_| Ok(())); // Rollback call

            let mut rpc = MockFakeRPCClient::new();
            rpc.expect_request_connect()
                .times(1)
                .returning(|_, _, _, _| {
                    Err(ConnectionError::CryptographicError(
                        "Mock RPC failure".to_string(),
                    ))
                });

            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submit(password, peer_did, own_did).await;

            // Should return original RPC error, not rollback error
            assert!(result.is_err());
            assert!(matches!(
                result.as_ref().unwrap_err(),
                ConnectionError::CryptographicError(_)
            ));

            // Verify error message contains original RPC error
            if let Err(ConnectionError::CryptographicError(msg)) = result {
                assert_eq!(msg, "Mock RPC failure");
            }
        }

        #[tokio::test]
        async fn test_request_submit_rpc_and_rollback_failure() {
            let mut repo = MockFakeRepo::new();
            repo.expect_save().times(1).returning(|_| Ok(()));
            repo.expect_remove().times(1).returning(|_| {
                Err(ConnectionError::EntityError(
                    "Mock rollback failure".to_string(),
                ))
            }); // Rollback fails

            let mut rpc = MockFakeRPCClient::new();
            rpc.expect_request_connect()
                .times(1)
                .returning(|_, _, _, _| {
                    Err(ConnectionError::CryptographicError(
                        "Mock RPC failure".to_string(),
                    ))
                });

            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submit(password, peer_did, own_did).await;

            // Should still return original RPC error, not rollback error
            assert!(result.is_err());
            assert!(matches!(
                result.as_ref().unwrap_err(),
                ConnectionError::CryptographicError(_)
            ));

            // Verify it's the original RPC error
            if let Err(ConnectionError::CryptographicError(msg)) = result {
                assert_eq!(msg, "Mock RPC failure");
            }
        }

        #[tokio::test]
        async fn test_request_submit_partial_connection_properties() {
            let mut repo = MockFakeRepo::new();
            repo.expect_save()
                .times(1)
                .withf(|connection: &Connection| {
                    // Validate partial connection properties
                    connection.get_state() == State::PendingOutgoing
                        && connection.get_peer_key().as_ref()
                            == "0000000000000000000000000000000000000000000000000000000000000000"
                        && connection.get_own_shared_secret().as_ref()
                            == Some(&OwnSharedSecret::from("pending".to_string()))
                        && connection.get_own_key().unwrap().as_ref().len() == 64
                        && connection.get_own_key().unwrap().as_ref()
                            != "0000000000000000000000000000000000000000000000000000000000000000"
                })
                .returning(|_| Ok(()));

            let mut rpc = MockFakeRPCClient::new();
            rpc.expect_request_connect()
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submit(password, peer_did, own_did).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_request_submit_invalid_peer_did_uri() {
            let repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();
            let (_password, _, _own_did) = create_valid_test_data();
            let _api = generate_connection_api(repo, rpc);

            // Test various invalid DID URI formats
            let invalid_dids = [
                "not-a-did",          // Missing did: prefix
                "",                   // Empty string
                "did:",               // Incomplete DID
                "did:invalid",        // Missing identifier
                "http://example.com", // Wrong scheme
                "did:example:",       // Missing identifier after method
            ];

            for invalid_did in invalid_dids {
                // This should fail at type construction level
                let result = PeerDIDURI::new(invalid_did.to_string());
                assert!(
                    result.is_err(),
                    "Should reject invalid DID: '{}'",
                    invalid_did
                );
            }
        }

        #[tokio::test]
        async fn test_request_submit_invalid_own_did_uri() {
            let repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();
            let (_password, _peer_did, _) = create_valid_test_data();
            let _api = generate_connection_api(repo, rpc);

            // Test invalid own DID URI
            let result = PeerDIDURI::new("invalid-did".to_string());
            assert!(result.is_err(), "Should reject invalid own DID URI");
        }

        #[tokio::test]
        async fn test_request_submit_connection_builder_cryptographic_error() {
            let repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            // Test with extremely long password that might cause cryptographic issues
            let problematic_password = "a".repeat(10000); // Very long password
            let (_, peer_did, own_did) = create_valid_test_data();

            let result = api
                .request_submit(problematic_password, peer_did, own_did)
                .await;

            // Should handle gracefully - either succeed or fail with proper error
            if result.is_err() {
                assert!(matches!(
                    result.unwrap_err(),
                    ConnectionError::CryptographicError(_) | ConnectionError::ValidationError(_)
                ));
            }
        }

        #[tokio::test]
        async fn test_request_submit_connection_id_generation_uniqueness() {
            let mut repo = MockFakeRepo::new();
            let mut rpc = MockFakeRPCClient::new();

            // Expect multiple saves with different connection IDs
            repo.expect_save().times(3).returning(|_| Ok(()));

            // Use Arc<Mutex<HashSet>> to allow shared mutable access
            let connection_ids =
                std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
            let connection_ids_clone = connection_ids.clone();

            rpc.expect_request_connect()
                .times(3)
                .withf(move |connection_id: &ConnectionID, _, _, _| {
                    let id_str = connection_id.as_ref().to_string();
                    let mut ids = connection_ids_clone.lock().unwrap();
                    let is_unique = !ids.contains(&id_str);
                    ids.insert(id_str);
                    is_unique && !connection_id.as_ref().is_empty()
                })
                .returning(|_, _, _, _| Ok(()));

            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            // Submit multiple requests and verify unique IDs
            for _ in 0..3 {
                let result = api
                    .request_submit(password.clone(), peer_did.clone(), own_did.clone())
                    .await;
                assert!(result.is_ok());
            }
        }

        #[tokio::test]
        async fn test_request_submit_public_key_extraction_validation() {
            let mut repo = MockFakeRepo::new();
            repo.expect_save().times(1).returning(|_| Ok(()));

            let mut rpc = MockFakeRPCClient::new();
            rpc.expect_request_connect()
                .times(1)
                .withf(|_, _, _, sender_key: &PeerKey| {
                    let key_str = sender_key.as_ref();
                    // Validate public key properties
                    key_str.len() == 64 &&                    // Correct length
                    key_str.chars().all(|c| c.is_ascii_hexdigit()) && // All hex characters
                    key_str != "0000000000000000000000000000000000000000000000000000000000000000" && // Not all zeros
                    key_str != "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    // Not all ones
                })
                .returning(|_, _, _, _| Ok(()));

            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submit(password, peer_did, own_did).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_request_submit_rpc_parameter_order_validation() {
            let mut repo = MockFakeRepo::new();
            repo.expect_save().times(1).returning(|_| Ok(()));

            let mut rpc = MockFakeRPCClient::new();
            rpc.expect_request_connect()
                .times(1)
                .withf(
                    |connection_id: &ConnectionID,
                     sender_did: &PeerDIDURI,
                     receiver_did: &PeerDIDURI,
                     _| {
                        // Verify parameter order: sender should be own_did, receiver should be peer_did
                        !connection_id.as_ref().is_empty() &&
                    sender_did.as_ref() == "did:example:987654321ihgfedcba" && // own_did
                    receiver_did.as_ref() == "did:example:123456789abcdefghi" // peer_did
                    },
                )
                .returning(|_, _, _, _| Ok(()));

            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submit(password, peer_did, own_did).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_request_submit_concurrent_requests() {
            use rst_common::with_tokio::tokio;
            use std::sync::Arc;

            let mut repo = MockFakeRepo::new();
            let mut rpc = MockFakeRPCClient::new();

            // Expect multiple concurrent saves
            repo.expect_save().times(5).returning(|_| Ok(()));

            rpc.expect_request_connect()
                .times(5)
                .returning(|_, _, _, _| Ok(()));

            let (password, peer_did, own_did) = create_valid_test_data();
            let api = Arc::new(generate_connection_api(repo, rpc));

            // Launch multiple concurrent requests
            let mut handles = vec![];
            for _ in 0..5 {
                let api_clone = api.clone();
                let password_clone = password.clone();
                let peer_did_clone = peer_did.clone();
                let own_did_clone = own_did.clone();

                let handle = tokio::spawn(async move {
                    api_clone
                        .request_submit(password_clone, peer_did_clone, own_did_clone)
                        .await
                });
                handles.push(handle);
            }

            // Wait for all requests to complete
            for handle in handles {
                let result = handle.await.unwrap();
                assert!(result.is_ok(), "Concurrent request should succeed");
            }
        }

        #[tokio::test]
        async fn test_request_submit_memory_cleanup_on_error() {
            let mut repo = MockFakeRepo::new();
            repo.expect_save()
                .times(1)
                .returning(|_| Err(ConnectionError::EntityError("Database full".to_string())));

            let rpc = MockFakeRPCClient::new();
            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submit(password, peer_did, own_did).await;

            // Verify error is properly propagated and no memory leaks
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::EntityError(_)
            ));

            // Connection should be dropped and not accessible
            // (Rust's ownership system ensures this, but good to document)
        }

        #[tokio::test]
        async fn test_request_submit_identical_did_uris_rejected() {
            // No mock expectations since validation should fail before any operations
            let repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();
            let (password, peer_did, _) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            // Test self-connection rejection
            let result = api
                .request_submit(
                    password,
                    peer_did.clone(),
                    peer_did, // Same as peer_did - should be rejected
                )
                .await;

            // Should fail with ValidationError
            assert!(result.is_err(), "Self-connection should be rejected");

            match result.unwrap_err() {
                ConnectionError::ValidationError(msg) => {
                    assert!(msg.contains("Cannot create connection to self"));
                    assert!(msg.contains("peer_did_uri and own_did_uri must be different"));
                }
                other => panic!("Expected ValidationError, got: {:?}", other),
            }
        }

        #[tokio::test]
        async fn test_request_submit_different_did_uris_allowed() {
            // This test ensures that different DIDs still work properly
            let mut repo = MockFakeRepo::new();
            repo.expect_save().times(1).returning(|_| Ok(()));

            let mut rpc = MockFakeRPCClient::new();
            rpc.expect_request_connect()
                .times(1)
                .returning(|_, _, _, _| Ok(()));

            let (password, peer_did, own_did) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            // Verify that different DIDs are still allowed
            assert_ne!(
                peer_did.as_ref(),
                own_did.as_ref(),
                "Test data should have different DIDs"
            );

            let result = api.request_submit(password, peer_did, own_did).await;
            assert!(result.is_ok(), "Different DIDs should be allowed");
        }

        #[tokio::test]
        async fn test_request_submit_self_connection_validation_early_return() {
            // Verify that self-connection validation happens BEFORE any processing
            // No mock expectations should be set since validation should fail immediately
            let repo = MockFakeRepo::new(); // No expectations = will panic if called
            let rpc = MockFakeRPCClient::new(); // No expectations = will panic if called

            let (password, peer_did, _) = create_valid_test_data();
            let api = generate_connection_api(repo, rpc);

            let result = api
                .request_submit(
                    password,
                    peer_did.clone(),
                    peer_did, // Self-connection
                )
                .await;

            // Should fail immediately without calling repo or RPC
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::ValidationError(_)
            ));

            // If we reach this point without panics, it means repo.save() and rpc.request_connect()
            // were never called, which is exactly what we want
        }
    }

    /// Tests for `request_connect` method
    mod request_connect_tests {
        use super::*;
        use rst_common::with_tokio::tokio;

        #[tokio::test]
        async fn test_request_connect_success() {
            let mut repo = MockFakeRepo::new();
            repo.expect_save()
                .times(1)
                .withf(|connection: &Connection| {
                    // Validate connection properties
                    connection.get_state() == State::PendingIncoming
                        && connection.get_own_key().is_none()
                        && connection.get_own_keysecure().is_none()
                        && connection.get_own_shared_secret().is_none()
                })
                .returning(|_| Ok(()));

            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            let connection_id = ConnectionID::generate();
            let sender_did_uri = PeerDIDURI::new("did:example:peer123".to_string()).unwrap();
            let sender_public_key = PeerKey::new(
                "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
            )
            .unwrap();

            let result = api
                .request_connect(
                    connection_id.clone(),
                    sender_did_uri.clone(),
                    sender_public_key.clone(),
                )
                .await;
            assert!(result.is_ok(), "request_connect should succeed");
        }

        #[tokio::test]
        async fn test_request_connect_invalid_connection_id() {
            let repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            let invalid_id = ConnectionID::from("not-a-uuid".to_string());
            let sender_did_uri = PeerDIDURI::new("did:example:peer123".to_string()).unwrap();
            let sender_public_key = PeerKey::new(
                "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
            )
            .unwrap();

            let result = api
                .request_connect(invalid_id, sender_did_uri, sender_public_key)
                .await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::ValidationError(_)
            ));
        }

        #[tokio::test]
        async fn test_request_connect_invalid_sender_did_uri() {
            let repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            let connection_id = ConnectionID::generate();
            let invalid_did_uri = PeerDIDURI::from_validated("invalid-did".to_string());
            let sender_public_key = PeerKey::new(
                "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
            )
            .unwrap();

            let result = api
                .request_connect(connection_id, invalid_did_uri, sender_public_key)
                .await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::ValidationError(_)
            ));
        }

        #[tokio::test]
        async fn test_request_connect_invalid_sender_public_key() {
            let repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            let connection_id = ConnectionID::generate();
            let sender_did_uri = PeerDIDURI::new("did:example:peer123".to_string()).unwrap();
            let invalid_public_key = PeerKey::from_validated("shortkey".to_string());

            let result = api
                .request_connect(connection_id, sender_did_uri, invalid_public_key)
                .await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::ValidationError(_)
            ));
        }

        #[tokio::test]
        async fn test_request_connect_repo_save_failure() {
            let mut repo = MockFakeRepo::new();
            repo.expect_save()
                .times(1)
                .returning(|_| Err(ConnectionError::EntityError("repo save failed".to_string())));

            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            let connection_id = ConnectionID::generate();
            let sender_did_uri = PeerDIDURI::new("did:example:peer123".to_string()).unwrap();
            let sender_public_key = PeerKey::new(
                "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
            )
            .unwrap();

            let result = api
                .request_connect(connection_id, sender_did_uri, sender_public_key)
                .await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::EntityError(_)
            ));
        }
    }

    /// Tests for `request_approval` method (when implemented)  
    mod request_approval_tests {
        use super::*;

        #[tokio::test]
        async fn test_request_approval_placeholder() {
            // Placeholder test for when method is implemented
            assert!(true, "Placeholder for request_approval tests");
        }
    }

    /// Tests for `request_response` method (when implemented)
    mod request_response_tests {
        use super::*;

        #[tokio::test]
        async fn test_request_response_placeholder() {
            // Placeholder test for when method is implemented
            assert!(true, "Placeholder for request_response tests");
        }
    }

    /// Tests for `request_submissions` method (using update_state for correct states)
    mod request_submissions_tests {
        use super::*;
        use rst_common::standard::uuid::Uuid;
        use rst_common::with_tokio::tokio;

        #[tokio::test]
        async fn test_request_submissions_success() {
            let mut repo = MockFakeRepo::new();

            // Create connections and update their states as needed
            let mut conn1 = Connection::builder()
                .with_id(ConnectionID::from(Uuid::new_v4().to_string()))
                .with_peer_did_uri(PeerDIDURI::new("did:example:peer1".to_string()).unwrap())
                .with_password("StrongPassword123!@#")
                .build()
                .unwrap();
            conn1.update_state(State::PendingOutgoing);

            let mut conn2 = Connection::builder()
                .with_id(ConnectionID::from(Uuid::new_v4().to_string()))
                .with_peer_did_uri(PeerDIDURI::new("did:example:peer2".to_string()).unwrap())
                .with_password("StrongPassword123!@#")
                .build()
                .unwrap();
            conn2.update_state(State::Established);

            let expected_connections = vec![conn1, conn2];

            repo.expect_list_connections()
                .times(1)
                .withf(|states| {
                    states.as_ref().unwrap().contains(&State::PendingOutgoing)
                        && states.as_ref().unwrap().contains(&State::Established)
                })
                .returning(move |_| Ok(expected_connections.clone()));

            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submissions().await;
            assert!(result.is_ok());
            let connections = result.unwrap();
            assert_eq!(connections.len(), 2);
            assert_eq!(connections[0].get_state(), State::PendingOutgoing);
            assert_eq!(connections[1].get_state(), State::Established);
        }

        #[tokio::test]
        async fn test_request_submissions_repo_error() {
            let mut repo = MockFakeRepo::new();
            repo.expect_list_connections()
                .times(1)
                .returning(|_| Err(ConnectionError::EntityError("repo error".to_string())));

            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_submissions().await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::EntityError(_)
            ));
        }
    }

    /// Tests for `request_list` method
    mod request_list_tests {
        use super::*;
        use rst_common::standard::uuid::Uuid;
        use rst_common::with_tokio::tokio;

        #[tokio::test]
        async fn test_request_list_success() {
            let mut repo = MockFakeRepo::new();

            // Create connections and update their states as needed
            let mut conn1 = Connection::builder()
                .with_id(ConnectionID::from(Uuid::new_v4().to_string()))
                .with_peer_did_uri(PeerDIDURI::new("did:example:peer3".to_string()).unwrap())
                .with_password("StrongPassword123!@#")
                .build()
                .unwrap();
            conn1.update_state(State::PendingIncoming);

            let mut conn2 = Connection::builder()
                .with_id(ConnectionID::from(Uuid::new_v4().to_string()))
                .with_peer_did_uri(PeerDIDURI::new("did:example:peer4".to_string()).unwrap())
                .with_password("StrongPassword123!@#")
                .build()
                .unwrap();
            conn2.update_state(State::Established);

            let expected_connections = vec![conn1, conn2];

            repo.expect_list_connections()
                .times(1)
                .withf(|states| {
                    states.as_ref().unwrap().contains(&State::PendingIncoming)
                        && states.as_ref().unwrap().contains(&State::Established)
                })
                .returning(move |_| Ok(expected_connections.clone()));

            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_list().await;
            assert!(result.is_ok());
            let connections = result.unwrap();
            assert_eq!(connections.len(), 2);
            assert_eq!(connections[0].get_state(), State::PendingIncoming);
            assert_eq!(connections[1].get_state(), State::Established);
        }

        #[tokio::test]
        async fn test_request_list_repo_error() {
            let mut repo = MockFakeRepo::new();
            repo.expect_list_connections()
                .times(1)
                .returning(|_| Err(ConnectionError::EntityError("repo error".to_string())));

            let rpc = MockFakeRPCClient::new();
            let api = generate_connection_api(repo, rpc);

            let result = api.request_list().await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::EntityError(_)
            ));
        }
    }

    /// Tests for `request_cancel` method
    mod request_cancel_tests {
        use super::*;
        use rst_common::with_tokio::tokio;

        #[tokio::test]
        async fn test_request_cancel_success() {
            let mut repo = MockFakeRepo::new();
            let mut rpc = MockFakeRPCClient::new();

            // Setup: repo returns a valid connection, rpc and repo.remove succeed
            repo.expect_get_connection_by_peer_conn_id()
                .times(1)
                .returning(|_| Ok(Connection::builder()
                    .with_id(ConnectionID::generate())
                    .with_peer_did_uri(PeerDIDURI::new("did:example:peer123".to_string()).unwrap())
                    .build().unwrap()));
            rpc.expect_request_remove()
                .times(1)
                .returning(|_, _| Ok(()));
            repo.expect_remove()
                .times(1)
                .returning(|_| Ok(()));

            let api = generate_connection_api(repo, rpc);
            let connection_id = ConnectionID::generate();

            let result = api.request_cancel(connection_id).await;
            assert!(result.is_ok(), "Cancellation should succeed");
        }

        #[tokio::test]
        async fn test_request_cancel_connection_not_found() {
            let mut repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();

            // Setup: repo returns not found error
            repo.expect_get_connection_by_peer_conn_id()
                .times(1)
                .returning(|_| Err(ConnectionError::InvalidConnectionID("not found".to_string())));

            let api = generate_connection_api(repo, rpc);
            let connection_id = ConnectionID::generate();

            let result = api.request_cancel(connection_id).await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::InvalidConnectionID(_)
            ));
        }

        #[tokio::test]
        async fn test_request_cancel_repo_error_other() {
            let mut repo = MockFakeRepo::new();
            let rpc = MockFakeRPCClient::new();

            // Setup: repo returns a generic error
            repo.expect_get_connection_by_peer_conn_id()
                .times(1)
                .returning(|_| Err(ConnectionError::EntityError("db error".to_string())));

            let api = generate_connection_api(repo, rpc);
            let connection_id = ConnectionID::generate();

            let result = api.request_cancel(connection_id).await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::EntityError(_)
            ));
        }

        #[tokio::test]
        async fn test_request_cancel_rpc_failure() {
            let mut repo = MockFakeRepo::new();
            let mut rpc = MockFakeRPCClient::new();

            // Setup: repo returns valid connection, rpc fails
            repo.expect_get_connection_by_peer_conn_id()
                .times(1)
                .returning(|_| Ok(Connection::builder()
                    .with_id(ConnectionID::generate())
                    .with_peer_did_uri(PeerDIDURI::new("did:example:peer123".to_string()).unwrap())
                    .build().unwrap()));
            rpc.expect_request_remove()
                .times(1)
                .returning(|_, _| Err(ConnectionError::EntityError("rpc failed".to_string())));

            let api = generate_connection_api(repo, rpc);
            let connection_id = ConnectionID::generate();

            let result = api.request_cancel(connection_id).await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::EntityError(_)
            ));
        }

        #[tokio::test]
        async fn test_request_cancel_remove_failure() {
            let mut repo = MockFakeRepo::new();
            let mut rpc = MockFakeRPCClient::new();

            // Setup: repo returns valid connection, rpc succeeds, repo.remove fails
            repo.expect_get_connection_by_peer_conn_id()
                .times(1)
                .returning(|_| Ok(Connection::builder()
                    .with_id(ConnectionID::generate())
                    .with_peer_did_uri(PeerDIDURI::new("did:example:peer123".to_string()).unwrap())
                    .build().unwrap()));
            rpc.expect_request_remove()
                .times(1)
                .returning(|_, _| Ok(()));
            repo.expect_remove()
                .times(1)
                .returning(|_| Err(ConnectionError::EntityError("remove failed".to_string())));

            let api = generate_connection_api(repo, rpc);
            let connection_id = ConnectionID::generate();

            let result = api.request_cancel(connection_id).await;
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                ConnectionError::EntityError(_)
            ));
        }
    }
}
