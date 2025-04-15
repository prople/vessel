//! `proof` module provides the `Proof` trait and its implementations.
//!
//! This module is responsible for handling the creation, validation, and management of verifiable proofs.
//!
//! The `Proof` itself will be used to for the `Presentation (VP)` and `Credential (VC)`. There are two important
//! objects, `Builder` and `Verifier`, which are responsible for creating and verifying the `Proof`.
pub mod builder;
pub mod types;
pub mod verifier;
