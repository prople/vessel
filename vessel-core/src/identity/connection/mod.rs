//! # Connection Module
//!
//! The `connection` module provides domain abstractions for maintaining secure, private 
//! connections between two peers in the vessel identity system.
//!
//! ## Overview
//!
//! This module implements the core functionality for establishing, managing, and maintaining
//! peer-to-peer connections with a focus on privacy and security. It handles the lifecycle
//! of connections from initial handshake through active communication and eventual teardown.
//!
//! ## Module Structure
//!
//! - [`types`] - Core data types and structures used throughout the connection system
//! - [`api`] - Public API interfaces for connection management operations
//! - [`connection`] - Core connection implementation and state management
//!
//! ## Key Features
//!
//! - **Privacy-First**: All connections are designed with privacy as a fundamental requirement
//! - **Peer-to-Peer**: Direct communication between peers without intermediaries
//! - **Secure**: Built-in security measures and encrypted communication channels
//! - **Lifecycle Management**: Complete connection lifecycle from establishment to termination
//!
//! ## Usage
//!
//! This module is typically used by higher-level identity management systems to establish
//! and maintain secure communication channels between identity holders.
//!
//! ```rust,ignore
//! use vessel_core::identity::connection::api::ConnectionManager;
//! 
//! // Example usage would go here once the API is stabilized
//! ```

pub mod types;
pub mod api;
pub mod connection;