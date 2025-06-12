use rst_common::standard::async_trait::async_trait;

use super::connection::Connection;
use super::types::{
    ConnectionAPI, ConnectionChallenge, ConnectionError, RepoBuilder, RpcBuilder, State,
    UsecaseBuilder,
};

#[derive(Clone)]
/// `Usecase` is base logic implementation for the [`AccountUsecaseBuilder`]
///
/// This object depends on the implementation of [`AccountRepositoryBuilder`]
pub struct Usecase<TRepo, TRPCClient>
where
    TRepo: RepoBuilder<EntityAccessor = Connection>,
    TRPCClient: RpcBuilder,
{
    repo: TRepo,
    rpc: TRPCClient,
}

impl<TRepo, TRPCClient> Usecase<TRepo, TRPCClient>
where
    TRepo: RepoBuilder<EntityAccessor = Connection>,
    TRPCClient: RpcBuilder,
{
    pub fn new(repo: TRepo, rpc: TRPCClient) -> Self {
        Self { repo, rpc }
    }
}

#[async_trait]
impl<TRepo, TRPCClient> UsecaseBuilder<Connection> for Usecase<TRepo, TRPCClient>
where
    TRepo: RepoBuilder<EntityAccessor = Connection>,
    TRPCClient: RpcBuilder + Send + Sync,
{
    type RepoImplementer = TRepo;
    type RPCImplementer = TRPCClient;

    fn repo(&self) -> Self::RepoImplementer {
        self.repo.clone()
    }

    fn rpc(&self) -> Self::RPCImplementer {
        self.rpc.clone()
    }
}

#[async_trait]
impl<TRepo, TRPCClient> ConnectionAPI for Usecase<TRepo, TRPCClient>
where
    TRepo: RepoBuilder<EntityAccessor = Connection>,
    TRPCClient: RpcBuilder + Send + Sync,
{
    type EntityAccessor = Connection;

    async fn submit_request(
        &self,
        _peer_did_uri: String,
        _own_did_uri: String,
    ) -> Result<ConnectionChallenge, ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn remove_request(&self, _id: String) -> Result<(), ConnectionError> {
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
        _peer_did_uri: String,
        _peer_public_key: String,
    ) -> Result<ConnectionChallenge, ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }

    async fn response_challenge(
        &self,
        _connection_id: String,
        _answer: String,
    ) -> Result<(), ConnectionError> {
        Err(ConnectionError::NotImplementedError)
    }
}
