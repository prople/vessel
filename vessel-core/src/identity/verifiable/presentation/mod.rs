//! `presentation` module provides the `Presentation` struct and related functionality.
//!
//! This module is responsible for handling the creation, validation, and management of verifiable presentations (VP).
//!
//! The presentation should be created by a `Holder` and will be send to some `Verifier`. Each of `VP` may only contains
//! multiple `VC` which are issued by the same `Issuer`. A `Verifier` will verify the `VP` and all of its `VC`, but for now
//! it will only verify the `VP` only.
mod presentation;
pub use presentation::Presentation;

mod verifier;
pub use verifier::Verifier;

pub mod types;
pub mod usecase;
