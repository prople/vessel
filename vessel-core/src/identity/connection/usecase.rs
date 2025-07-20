use rst_common::standard::async_trait::async_trait;

use super::connection::Connection;
use super::types::{
    ConnectionAPI, ConnectionChallenge, ConnectionError, RepoConnectionBuilder, RpcBuilder, State,
    UsecaseBuilder, ConnectionProposal, RepoChallengeBuilder
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

impl<TRepoConnection, TRepoChallenge, TRPCClient> Usecase<TRepoConnection, TRepoChallenge, TRPCClient>
where
    TRepoConnection: RepoConnectionBuilder<EntityAccessor = Connection>,
    TRepoChallenge: RepoChallengeBuilder,
    TRPCClient: RpcBuilder,
{
    pub fn new(repo_conn: TRepoConnection, repo_challenge: TRepoChallenge, rpc: TRPCClient) -> Self {
        Self { repo_conn, repo_challenge, rpc }
    }
}

#[async_trait]
impl<TRepoConnection, TRepoChallenge, TRPCClient> UsecaseBuilder<Connection> for Usecase<TRepoConnection, TRepoChallenge, TRPCClient>
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
impl<TRepoConnection, TRepoChallenge, TRPCClient> ConnectionAPI for Usecase<TRepoConnection, TRepoChallenge, TRPCClient>
where
    TRepoConnection: RepoConnectionBuilder<EntityAccessor = Connection>,
    TRepoChallenge: RepoChallengeBuilder,
    TRPCClient: RpcBuilder + Send + Sync,
{
    type EntityAccessor = Connection;

    async fn submit_request(
        &self,
        _peer_did_uri: String,
        _own_did_uri: String,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
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

    async fn request_connect(
        &self,
        _proposal: ConnectionProposal,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn response_challenge(
        &self,
        _password: String,
        _connection_id: String,
        _answer: String,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }
     
    async fn list_requests(
        &self,
    ) -> Result<Vec<Self::EntityAccessor>, ConnectionError> {
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
    
    async fn list_challenges(
        &self,
    ) -> Result<Vec<ConnectionChallenge>, ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }
    
    async fn cancel_request(
        &self,
        _proposal_id: String,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }    
}
