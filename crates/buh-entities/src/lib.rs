//! buh domain types, DTOs, and error enums.
//!
//! This crate is pure: no I/O, no async runtime, no network or database dependencies.
//! Everything downstream (`buh-core`, `buh-data`, the binaries, and — via generated
//! bindings — the web client) depends on it. Request/response types live here so clients
//! can share them.
//!
//! The defining constraint of buh is that **the node is untrusted and blind**. The types
//! here reflect that: a relay deals only in opaque [`QueueId`]s and opaque envelope payload
//! bytes. There is no user, sender, or social-graph type, because the relay never learns
//! any of those things (see `doc/design.md` §3.1).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod b64;
pub mod dto;
pub mod envelope;
pub mod error;
pub mod ids;
pub mod queue;
pub mod settlement;

pub use dto::{AckAccepted, EnvelopeAccepted, PullResponse, PushEnvelope};
pub use envelope::{DeliveryReceipt, NewEnvelope, StoredEnvelope};
pub use error::EntityError;
pub use ids::EnvelopeId;
pub use queue::QueueId;
pub use settlement::{Credit, DepositInstructions, DepositProof, Payout, SolvencyProof, TxRef};
