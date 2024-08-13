use std::fmt::Debug;

use multiaddr::Multiaddr;

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde_json::value::Value;
use rst_common::with_errors::thiserror::{self, Error};

use rstdev_domain::entity::ToJSON;

use prople_crypto::keysecure::KeySecure;
use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::verifiable::objects::VC;

use crate::identity::account::types::{AccountAPI, AccountEntityAccessor};
use crate::identity::verifiable::proof::types::Params as ProofParams;
use crate::identity::verifiable::types::{PaginationParams, VerifiableError};

#[derive(Debug, Error, Clone)]
pub enum CredentialError {
    #[error("unable to generate credential: {0}")]
    GenerateError(String),

    #[error("json error: {0}")]
    GenerateJSONError(String),

    #[error("unable to process incoming vc: {0}")]
    ReceiveError(String),

    #[error("unable to process holder: {0}")]
    HolderError(String),

    #[error("unable to send vc: {0}")]
    SendError(String),

    #[error("unable to confirm vc: {0}")]
    ConfirmError(String),

    #[error("unable to verify vc: {0}")]
    VerifyError(String),

    #[error("unable to list vc: {0}")]
    ListError(String),

    #[error("unable unserialize account: {0}")]
    UnserializeError(String),

    #[error("common error: {0}")]
    CommonError(#[from] VerifiableError),

    #[error("credential not found")]
    CredentialNotFound,
}

/// `CredentialEntityAccessor` it's an interface used as a getter objects
/// for all `Credential` property fields
pub trait CredentialEntityAccessor:
    Clone + Debug + ToJSON + TryInto<Vec<u8>> + TryFrom<Vec<u8>>
{
    fn get_id(&self) -> String;
    fn get_did_issuer(&self) -> String;
    fn get_did_vc(&self) -> String;
    fn get_did_vc_doc_private_keys(&self) -> IdentityPrivateKeyPairs;
    fn get_vc(&self) -> VC;
    fn get_keysecure(&self) -> KeySecure;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

/// `HolderEntityAccessor`  it's an interface used as a getter object for all `Holder` property
/// fields
pub trait HolderEntityAccessor:
    Clone + Debug + ToJSON + TryInto<Vec<u8>> + TryFrom<Vec<u8>>
{
    fn get_id(&self) -> String;
    fn get_vc(&self) -> VC;
    fn get_is_verified(&self) -> bool;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

#[async_trait]
pub trait CredentialAPI: Clone {
    type EntityAccessor: CredentialEntityAccessor;

    /// `generate_credential` used to generate the `Verifiable Credential` and [`Credential`] object
    /// entity. The generated credential entity should be saved into persistent storage through
    /// our implementer of [`VerifiableRepoBuilder`]
    ///
    /// The `credential` is an object of [`Value`], it can be anything that able to convert to `serde_json::value::Value`
    /// The `proof_params` is an optional parameter, if an user want to generate a `VC` with its [`Proof`], it must
    /// be set, but if not, just left it `None`
    async fn generate_credential(
        &self,
        password: String,
        did_issuer: String,
        credential: Value,
        proof_params: Option<ProofParams>,
    ) -> Result<Self::EntityAccessor, CredentialError>;

    /// `send_credential_to_holder` used to send a `VC` to some `Holder`, if there is no error it means the `VC`
    /// already received successfully.
    ///
    /// The communiation itself must be happened through [`VerifiableRPCBuilder::vc_send_to`], the implementation
    /// of this RPC client must call the RPC method of `vc.receive` belongs to `Holder`
    ///
    /// The `VC` that need to send to the `Holder` should be loaded from our persistent storage
    /// based on given `id` which is the id of [`Credential`]
    async fn send_credential_to_holder(
        &self,
        id: String,
        did_uri: String,
    ) -> Result<(), CredentialError>;

    /// `receive_credential_by_holder` used by `Holder` to receive incoming [`VC`] from an `Issuer` and save it
    /// to the persistent storage through `CredentialHolder`
    async fn receive_credential_by_holder(
        &self,
        did_holder: String,
        vc: VC,
    ) -> Result<(), CredentialError>;

    /// `verify_credential_by_holder` used by `Holder` to verify its received `VC`
    async fn verify_credential_by_holder(&self, id: String) -> Result<(), CredentialError>;

    /// `list_credentials_by_did` used to load a list of saved `VC` based on `DID` issuer
    ///
    /// This method doesn't contain any logic, actually this method is just a simple proxy
    /// to the repository method, [`VerifiableRepoBuilder::list_by_did`]
    async fn list_credentials_by_did(
        &self,
        did: String,
        pagination: Option<PaginationParams>,
    ) -> Result<Vec<Self::EntityAccessor>, CredentialError>;

    /// `list_credentials_by_ids` used to load a list of saved `VC` based on `DID` issuer
    ///
    /// This method doesn't contain any logic, actually this method is just a simple proxy
    /// to the repository method, [`VerifiableRepoBuilder::list_by_did`]
    async fn list_credentials_by_ids(
        &self,
        ids: Vec<String>,
    ) -> Result<Vec<Self::EntityAccessor>, CredentialError>;
}

#[async_trait]
pub trait RepoBuilder: Clone + Sync + Send {
    type CredentialEntityAccessor: CredentialEntityAccessor;
    type HolderEntityAccessor: HolderEntityAccessor;

    async fn save_credential(
        &self,
        data: &Self::CredentialEntityAccessor,
    ) -> Result<(), CredentialError>;

    async fn save_credential_holder(
        &self,
        data: &Self::HolderEntityAccessor,
    ) -> Result<(), CredentialError>;

    async fn set_credential_holder_verified(
        &self,
        holder: &Self::HolderEntityAccessor,
    ) -> Result<(), CredentialError>;

    async fn remove_credential_by_id(&self, id: String) -> Result<(), CredentialError>;

    async fn get_credential_by_id(
        &self,
        id: String,
    ) -> Result<Self::CredentialEntityAccessor, CredentialError>;

    async fn get_holder_by_id(
        &self,
        id: String,
    ) -> Result<Self::HolderEntityAccessor, CredentialError>;

    async fn list_credentials_by_ids(
        &self,
        ids: Vec<String>,
    ) -> Result<Vec<Self::CredentialEntityAccessor>, CredentialError>;

    async fn list_credentials_by_did(
        &self,
        did: String,
        pagination: Option<PaginationParams>,
    ) -> Result<Vec<Self::CredentialEntityAccessor>, CredentialError>;
}

#[async_trait]
pub trait RpcBuilder: Clone + Sync + Send {
    async fn send_credential_to_holder(
        &self,
        did_holder: String,
        addr: Multiaddr,
        vc: VC,
    ) -> Result<(), CredentialError>;

    async fn verify_credential_to_issuer(
        &self,
        addr: Multiaddr,
        vc: VC,
    ) -> Result<(), CredentialError>;
}

/// `CredentialUsecaseBuilder` is a main trait to build the usecase business logic
/// for the `Verifiable` domain. This trait will inherit trait behaviors from [`AccountUsecaseEntryPoint`]
/// this mean, the implementer need to define the `Implementer` type and define how to
/// get the `AccountUsecase` object
///
/// This trait will maintain all logic that relate with the `VC (Verifiable Credential)` and also
/// `VP (Verifiable Presentation)`
#[async_trait]
pub trait UsecaseBuilder<TAccountEntity, TCredentialEntity, THolderEntity>:
    CredentialAPI<EntityAccessor = TCredentialEntity>
where
    TAccountEntity: AccountEntityAccessor,
    TCredentialEntity: CredentialEntityAccessor,
    THolderEntity: HolderEntityAccessor,
{
    type AccountAPIImplementer: AccountAPI;
    type RepoImplementer: RepoBuilder<
        CredentialEntityAccessor = TCredentialEntity,
        HolderEntityAccessor = THolderEntity,
    >;
    type RPCImplementer: RpcBuilder;

    fn account(&self) -> Self::AccountAPIImplementer;
    fn repo(&self) -> Self::RepoImplementer;
    fn rpc(&self) -> Self::RPCImplementer;
}
