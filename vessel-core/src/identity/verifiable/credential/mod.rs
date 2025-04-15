//! `credential` module provides the `Credential` struct and related functionality.
//!
//! This module is responsible for handling the creation, validation, and management of verifiable credentials (VC).
//!
//! The credential should be issued only by a `Issuer`, generate its `VC` and will be send to some `Holder`
mod credential;
pub use credential::Credential;

mod holder;
pub use holder::Holder;

mod usecase;
pub use usecase::Usecase;

pub mod types;
