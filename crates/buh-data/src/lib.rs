//! Data-access adapters for buh.
//!
//! Implements the port traits declared in [`buh_core::ports`] over an embedded Turso
//! datastore (the pure-Rust, SQLite-compatible engine). Owns all persistence I/O; the
//! binaries wire a [`stack::DataStack`] and hand its [`buh_core::Ctx`] to the business logic.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod migrate;
mod stack;
mod turso_mailbox;

pub use stack::DataStack;
pub use turso_mailbox::TursoMailboxRepo;
