//! Data-access adapters for buh.
//!
//! Implements the port traits declared in [`buh_core::ports`] over an embedded Turso
//! datastore (the pure-Rust, SQLite-compatible engine). Owns all persistence I/O; the
//! binaries wire a [`stack::DataStack`] and hand its [`buh_core::Ctx`] to the business logic.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod fs_blob;
mod migrate;
mod node_ca;
mod peer_trust;
mod stack;
mod stub_settlement;
mod turso_mailbox;

#[cfg(feature = "s3")]
mod s3_blob;

pub use fs_blob::FsBlobStore;
pub use node_ca::{RcgenNodeCa, fingerprint};
pub use peer_trust::TursoPeerTrust;
pub use stack::DataStack;
pub use stub_settlement::StubSettlement;
pub use turso_mailbox::TursoMailboxRepo;

#[cfg(feature = "s3")]
pub use s3_blob::{S3BlobStore, S3Settings};
