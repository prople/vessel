use prople_crypto::keysecure::KeySecure;

use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};
use rst_common::standard::uuid::Uuid;
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
}

/// `Account` is main entity data structure
///
/// This entity will able to define user/person, organization
/// machine, everything. For the non-human data identity, it should
/// has it's own controller
#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "self::serde")]
pub struct Account {
    pub id: String,
    pub did: String,
    pub keysecure: KeySecure,

    #[serde(with = "ts_seconds")]
    pub created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

impl Account {
    pub fn new(did: String, keysecure: KeySecure) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            did,
            keysecure,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// `AccountUsecaseBuilder` is a trait behavior that provides
/// basic logic for the account management activities
pub trait AccountUsecaseBuilder {
    /// `generate_did` used to geenerate new `DID Account`
    /// 
    /// This method will depends on two parameters:
    /// - `address`
    /// - `password`
    /// 
    /// The `address` should be an address of current running vessel,
    /// it can be a multiaddress format from libp2p or common HTTP API address.
    /// This property will be embedded inside user's `DID Account` syntax, so
    /// other people will know how to resolve the DID 
    /// 
    /// The `password` used to save the generated private key pair into encrypted
    /// storage data structure. This strategy following `Ethereum KeyStore` mechanism.
    /// This property will be used to generate hash that will be used as a key to encrypt
    /// and decrypt the generated private key
    fn generate_did(&self, address: String, password: String) -> Result<Account, AccountError>;
}

/// `AccountRepository` is a trait behavior that used as base
/// repository interface.
///
/// The repository used to save and fetch the data to and from
/// persistent storage. User should be able to choose their selected
/// persistent storage or database such as SQL or NoSQL
pub trait AccountRepositoryBuilder {
    fn save(&self, account: &Account) -> Result<(), AccountError>;
}
