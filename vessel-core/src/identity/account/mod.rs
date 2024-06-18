//! `account` is a sub-domain of `ssi` which focus to manage the `DID` entity account.
//!
//! This domain will have multiple use cases:
//!
//! - Generate the `DID` accounts including for it's `DID Doc`
//! - Resolve `DID`, including for the validation
//! - Update `DID` account metadata
//! - Remove / delete `DID`
pub mod types;
pub mod usecase;

mod uri;
pub use uri::URI;

mod account;
pub use account::Account;
