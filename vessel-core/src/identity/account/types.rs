use std::fmt::Debug;

use multiaddr::Multiaddr;
use rst_common::standard::async_trait::async_trait;

use prople_crypto::keysecure::KeySecure;
use prople_did_core::doc::types::Doc;
use prople_did_core::{did::query::Params, keys::IdentityPrivateKeyPairs};

use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::with_errors::thiserror::{self, Error};

/// `AccountError` provides all specific error types relate with entity account
/// management
#[derive(Debug, PartialEq, Error)]
pub enum AccountError {
    #[error("unknown error: {0}")]
    UnknownError(String),

    #[error("unable to resolve did: {0}")]
    ResolveDIDError(String),

    #[error("unable to remove did: {0}")]
    RemoveDIDError(String),

    #[error("unable to update did: {0}")]
    UpdateDIDError(String),

    #[error("unable to save account: {0}")]
    SaveAccountError(String),

    #[error("trait method not implemented: {0}")]
    TraitMethodNotImplemented(String),

    #[error("unable to generate identity: {0}")]
    GenerateIdentityError(String),

    #[error("unable to build DID uri: {0}")]
    BuildURIError(String),

    #[error("unknown DID")]
    DIDNotFound,
}

/// `AccountEntityAccessor` it's a special trait used to access [`Account`]
/// property fields. This entity  will be useful from the outside of this crate
/// to access those fields because we need to protect the properties from direct
/// access or manipulation from outside
pub trait AccountEntityAccessor: Clone + Debug {
    fn get_id(&self) -> String;
    fn get_did(&self) -> String;
    fn get_doc(&self) -> Doc;
    fn get_doc_private_keys(&self) -> IdentityPrivateKeyPairs;
    fn get_keysecure(&self) -> KeySecure;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

/// `AccountUsecaseBuilder` is a trait behavior that provides
/// base application logic's handlers
#[async_trait]
pub trait UsecaseBuilder<TEntityAccessor>
where
    TEntityAccessor: AccountEntityAccessor,
{
    /// `generate_did` used to geenerate new `DID Account`
    ///
    /// This method will depends on two parameters:
    /// - `password`
    ///
    /// The `password` used to save the generated private key pair into encrypted
    /// storage data structure. This strategy following `Ethereum KeyStore` mechanism.
    /// This property will be used to generate hash that will be used as a key to encrypt
    /// and decrypt the generated private key
    async fn generate_did(&self, password: String) -> Result<TEntityAccessor, AccountError>;

    /// `build_did_uri` used to generate the `DID URI`, a specific URI syntax for the DID
    ///
    /// Example
    ///
    /// ```text
    /// did:prople:<base58_encoded_data>?service=peer&address=<multiaddr_format>&hl=<hashed_link>
    /// ```
    async fn build_did_uri(
        &self,
        did: String,
        password: String,
        params: Option<Params>,
    ) -> Result<String, AccountError>;

    /// `resolve_did_uri` used to resolve given `DID URI` and must be able to return `DID DOC`
    /// by calling an `JSON-RPC` method of `resolve_did_doc` to oher `Vessel Agent`
    async fn resolve_did_uri(&self, uri: String) -> Result<Doc, AccountError>;

    /// `resolve_did_doc` used to get saved `DID DOC` based on given `DID Account`
    async fn resolve_did_doc(&self, did: String) -> Result<Doc, AccountError>;

    /// `remove_did` used to remove saved [`Account`] based on given `DID`
    async fn remove_did(&self, did: String) -> Result<(), AccountError>;

    /// `get_account_did` used to load data [`Account`] from its persistent storage
    async fn get_account_did(&self, did: String) -> Result<TEntityAccessor, AccountError>;
}

/// `AccountUsecaseImplementer` it's a simple trait used as parent super trait by other
/// traits that need to inherit from the [`AccountUsecaseBuilder`]
pub trait UsecaseImplementer {
    type Accessor: AccountEntityAccessor;
    type Implementer: UsecaseBuilder<Self::Accessor>;

    fn account(&self) -> Self::Implementer;
}

/// `AccountRepository` is a trait behavior that used as base
/// repository interface.
///
/// The repository used to save and fetch the data to and from
/// persistent storage. User should be able to choose their selected
/// persistent storage or database such as SQL or NoSQL
#[async_trait]
pub trait RepositoryBuilder
{
    type EntityAccessor: AccountEntityAccessor;

    async fn save_account(&self, account: &Self::EntityAccessor) -> Result<(), AccountError>;
    async fn remove_account_by_did(&self, did: String) -> Result<(), AccountError>;
    async fn get_account_by_did(&self, did: String) -> Result<Self::EntityAccessor, AccountError>;
}

/// `AccountRPCClientBuilder` is a trait behavior used as `JSON-RPC` client builder
/// to calling other `Vessel` agents.
#[async_trait]
pub trait RPCClientBuilder {
    async fn resolve_did_doc(&self, addr: Multiaddr, did: String) -> Result<Doc, AccountError>;
}
