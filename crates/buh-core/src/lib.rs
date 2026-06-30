//! buh business logic and port traits.
//!
//! Consumes [`buh_entities`]. Defines the ports (`MailboxRepo`, `BlobStore`,
//! `SettlementBackend`) that `buh-data` implements, and the thin relay orchestration. No
//! direct database, object-store, or network I/O lives here.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod context;
pub mod error;
pub mod mailbox;
pub mod ports;

pub use context::{CoreConfig, Ctx};
pub use error::{CoreError, CoreResult};
pub use ports::{BlobStore, MailboxRepo, SettlementBackend};
