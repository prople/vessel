//! `identity` is a sub-domain used to manage identity which following the framework of 
//! `SSI (Self Sovereign Identity)` based on `DID Framework`
//!
//! The `SSI (Self Sovereign Identity)` has three sub-domain in it:
//!
//! - `verifiable`
//! - `account`
//! - `connection`
//!
//! ---
//!  
//! The `agent` is a digital representative of some entities. The `agent` domain
//! will maintain communication between the controller and their agents, including
//! for agent-to-agent communication through `DIDComm Messaging`.
//!
//! The `agent` domain should be focus only to `SSI` and `DID` things, and should not need to care
//! about anything else outside of it's domains, something like `PDS (Personal Data Storage)`,
//! including for `Social` and `Financial` activities. The `agent` defined at this domain
//! will focus only to the entity **identity** and the peer-to-peer identity communication
//! through `DIDComm Messaging`
//! 
//! ---
//! 
//! The `verifiable` sub-domain is a domain that focus on managing the `VC` and `VP` for the generation
//! and also verifying data including for sending and receiving credentials
//!
//! ---
//!  
//! The `account` is primary `DID` account of some entities. This domain will maintain
//! the account in `DID Syntax` including for the `DID VC (Verifiable Credential)`
//! and `DID VP (Verifiable Presentation)`. There are three important concepts that need to
//! be managed:
//!
//! - The **Issuer**, is an entity who generate the `VC`.
//! - The **Holder**, is an entity who hold the `VC` and generate the `VP`
//! - The **Verifier**, is an entity which need to prove the given `VP` from **Holder* including communicate
//! with the **Issuer** too
//!
//! All of `DID` implementation will be managed through library `prople-did-core`. This current **crate** will
//! be used only as the primary logic behind request and response used at `Vessel RPC`
//!
//! ---
//!  
//! The `connection` domain will be used to maintain the connection management between entities.
//! For an example, there are two users that want to be connected, `Alice` and `Bob`. `Alice`
//! want to connect to `Bob`, so `Alice` need to sending a connection request through her agent, to
//! the bob's agent. `Bob` should be able to get the notification if there a connection request comes
//! from `Alice`, and able to decide  to reject or approve the connection. Once the connection established
//! they will generate the `VC` and `VP` with it's proofs which contains a digital signature, which means
//! they need to exchange their public keys.
pub mod account;
pub mod verifiable;