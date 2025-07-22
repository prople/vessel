use rst_common::standard::async_trait::async_trait;

use crate::identity::connection::types::ConnectionEntityAccessor;

use super::connection::Connection;
use super::types::{
    ConnectionAPI, ConnectionChallenge, ConnectionError, ConnectionProposal, RepoChallengeBuilder,
    RepoConnectionBuilder, RpcBuilder, State, UsecaseBuilder, CONTEXT_CONNECTION_REQUEST,
};

#[derive(Clone)]
/// `Usecase` is base logic implementation for the [`AccountUsecaseBuilder`]
///
/// This object depends on the implementation of [`AccountRepositoryBuilder`]
pub struct Usecase<TRepoConnection, TRepoChallenge, TRPCClient>
where
    TRepoConnection: RepoConnectionBuilder<EntityAccessor = Connection>,
    TRepoChallenge: RepoChallengeBuilder,
    TRPCClient: RpcBuilder,
{
    repo_conn: TRepoConnection,
    repo_challenge: TRepoChallenge,
    rpc: TRPCClient,
}

impl<TRepoConnection, TRepoChallenge, TRPCClient>
    Usecase<TRepoConnection, TRepoChallenge, TRPCClient>
where
    TRepoConnection: RepoConnectionBuilder<EntityAccessor = Connection>,
    TRepoChallenge: RepoChallengeBuilder,
    TRPCClient: RpcBuilder,
{
    pub fn new(
        repo_conn: TRepoConnection,
        repo_challenge: TRepoChallenge,
        rpc: TRPCClient,
    ) -> Self {
        Self {
            repo_conn,
            repo_challenge,
            rpc,
        }
    }
}

#[async_trait]
impl<TRepoConnection, TRepoChallenge, TRPCClient> UsecaseBuilder<Connection>
    for Usecase<TRepoConnection, TRepoChallenge, TRPCClient>
where
    TRepoConnection: RepoConnectionBuilder<EntityAccessor = Connection>,
    TRepoChallenge: RepoChallengeBuilder,
    TRPCClient: RpcBuilder + Send + Sync,
{
    type RepoConnectionImplementer = TRepoConnection;
    type RepoChallengeImplementer = TRepoChallenge;
    type RPCImplementer = TRPCClient;

    fn repo_connection(&self) -> Self::RepoConnectionImplementer {
        self.repo_conn.clone()
    }

    fn repo_challenge(&self) -> Self::RepoChallengeImplementer {
        self.repo_challenge.clone()
    }

    fn rpc(&self) -> Self::RPCImplementer {
        self.rpc.clone()
    }
}

#[async_trait]
impl<TRepoConnection, TRepoChallenge, TRPCClient> ConnectionAPI
    for Usecase<TRepoConnection, TRepoChallenge, TRPCClient>
where
    TRepoConnection: RepoConnectionBuilder<EntityAccessor = Connection>,
    TRepoChallenge: RepoChallengeBuilder,
    TRPCClient: RpcBuilder + Send + Sync,
{
    type EntityAccessor = Connection;

    async fn submit_request(
        &self,
        password: String,
        peer_did_uri: String,
    ) -> Result<(), ConnectionError> {
        let mut connection = Connection::generate(password, peer_did_uri.clone())?;

        let proposal = ConnectionProposal::new(
            connection.get_own_key().ok_or_else(|| {
                ConnectionError::EntityError("Own key is missing".to_string())
            })?,
            peer_did_uri,
            CONTEXT_CONNECTION_REQUEST,
        );

        // use rpc to send the proposal to our peer
        // we better to wait the response from the peer
        // if the peer accepts the proposal, we continue to save the connection 
        self.rpc().request_connect(proposal.clone()).await?;

        // if the rpc call is successful, we save the connection including for its proposal
        _ = connection.set_proposal(proposal);
        self.repo_connection()
            .save(&connection)
            .await
            .map_err(|err| ConnectionError::EntityError(err.to_string()))
    }

    async fn remove_proposal(&self, _proposal_id: String) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn get_connection(&self, _id: String) -> Result<Self::EntityAccessor, ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn list_connections(
        &self,
        _state: Option<State>,
    ) -> Result<Vec<Self::EntityAccessor>, ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn request_connect(&self,proposal: ConnectionProposal) -> Result<(), ConnectionError> {
        let mut connection = Connection::generate_without_password(proposal.get_did_uri())?;
        connection.set_proposal(proposal);

        self.repo_connection()
            .save(&connection)
            .await
            .map_err(|err| ConnectionError::EntityError(err.to_string()))
    }

    async fn response_challenge(
        &self,
        _password: String,
        _connection_id: String,
        _answer: String,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn list_requests(&self) -> Result<Vec<Self::EntityAccessor>, ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn response_request(
        &self,
        _connection_id: String,
        _accepted: bool,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn answer_challenge(
        &self,
        _connection_id: String,
        _answer: String,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn request_challenge(
        &self,
        _challenge: ConnectionChallenge,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn list_challenges(&self) -> Result<Vec<ConnectionChallenge>, ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn cancel_request(&self, _proposal_id: String) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }
}
