use multiaddr::Multiaddr;

use rst_common::standard::async_trait::async_trait;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde_json::value::Value;

use prople_crypto::keysecure::KeySecure;
use prople_did_core::keys::IdentityPrivateKeyPairs;
use prople_did_core::verifiable::objects::VC;

use crate::identity::account::types::{AccountAPI, AccountEntityAccessor};
use crate::identity::verifiable::proof::types::Params as ProofParams;
use crate::identity::verifiable::types::{PaginationParams, VerifiableError};

/// `CredentialEntityAccessor` it's an interface used as a getter objects
/// for all `Credential` property fields
pub trait CredentialEntityAccessor {
    fn get_id(&self) -> String;
    fn get_did(&self) -> String;
    fn get_did_vc(&self) -> String;
    fn get_did_vc_doc_private_keys(&self) -> IdentityPrivateKeyPairs;
    fn get_vc(&self) -> VC;
    fn get_keysecure(&self) -> KeySecure;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

/// `HolderEntityAccessor`  it's an interface used as a getter object for all `Holder` property
/// fields
pub trait HolderEntityAccessor {
    fn get_id(&self) -> String;
    fn get_vc(&self) -> VC;
    fn get_request_id(&self) -> String;
    fn get_issuer_addr(&self) -> Multiaddr;
    fn get_created_at(&self) -> DateTime<Utc>;
    fn get_updated_at(&self) -> DateTime<Utc>;
}

#[async_trait]
pub trait CredentialAPI {
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
    ) -> Result<Self::EntityAccessor, VerifiableError>;

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
        receiver: Multiaddr,
    ) -> Result<(), VerifiableError>;

    /// `receive_credential_by_holder` used by `Holder` to receive incoming [`VC`] from an `Issuer` and save it
    /// to the persistent storage through `CredentialHolder`
    async fn receive_credential_by_holder(
        &self,
        request_id: String,
        issuer_addr: String,
        vc: VC,
    ) -> Result<(), VerifiableError>;

    /// `list_credentials` used to load a list of saved `VC` based on `DID` issuer
    ///
    /// This method doesn't contain any logic, actually this method is just a simple proxy
    /// to the repository method, [`VerifiableRepoBuilder::list_by_did`]
    async fn list_credentials(
        &self,
        did: String,
        pagination: Option<PaginationParams>,
    ) -> Result<Vec<Self::EntityAccessor>, VerifiableError>;
}

#[async_trait]
pub trait RepoBuilder {
    type CredentialEntityAccessor: CredentialEntityAccessor;
    type HolderEntityAccessor: HolderEntityAccessor;

    async fn save_credential(
        &self,
        data: &Self::CredentialEntityAccessor,
    ) -> Result<(), VerifiableError>;
    async fn save_credential_holder(
        &self,
        data: &Self::HolderEntityAccessor,
    ) -> Result<(), VerifiableError>;
    async fn remove_credential_by_id(&self, id: String) -> Result<(), VerifiableError>;
    async fn remove_credential_by_did(&self, did: String) -> Result<(), VerifiableError>;

    async fn get_credential_by_id(
        &self,
        id: String,
    ) -> Result<Self::CredentialEntityAccessor, VerifiableError>;

    async fn list_credentials_by_ids(
        &self,
        ids: Vec<String>,
    ) -> Result<Vec<Self::CredentialEntityAccessor>, VerifiableError>;

    async fn list_credentials_by_did(
        &self,
        did: String,
        pagination: Option<PaginationParams>,
    ) -> Result<Vec<Self::CredentialEntityAccessor>, VerifiableError>;
}

#[async_trait]
pub trait RPCBuilder {
    async fn send_credential_to_holder(
        &self,
        addr: Multiaddr,
        vc: VC,
    ) -> Result<(), VerifiableError>;

    async fn verify_credential_to_issuer(
        &self,
        addr: Multiaddr,
        vc: VC,
    ) -> Result<(), VerifiableError>;
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
        > + Clone
        + Sync
        + Send;
    type RPCImplementer: RPCBuilder + Clone + Sync + Send;

    fn account(&self) -> Self::AccountAPIImplementer;
    fn repo(&self) -> Self::RepoImplementer;
    fn rpc(&self) -> Self::RPCImplementer;
}
