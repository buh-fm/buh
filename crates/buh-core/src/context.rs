//! The dependency-injection context that bundles the port implementations.
//!
//! Binaries construct a [`Ctx`] once at startup from the `data` adapters and pass `&Ctx` to
//! the business-logic functions. Tests construct one from in-memory fakes.

use std::sync::Arc;

use crate::ports::{BlobStore, MailboxRepo};

/// Non-secret tuning knobs for relay logic.
#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// TTL applied when a client requests none (or one out of range), in seconds.
    pub default_ttl_seconds: i64,
    /// Maximum TTL a client may request, in seconds.
    pub max_ttl_seconds: i64,
    /// Maximum accepted envelope payload size, in bytes (envelopes are small by design).
    pub max_payload_bytes: usize,
    /// Maximum number of envelopes returned by a single pull.
    pub max_pull_limit: i64,
    /// Maximum accepted media blob size, in bytes (media is large but bounded).
    pub max_blob_bytes: usize,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 60 * 60 * 24 * 7, // 7 days
            max_ttl_seconds: 60 * 60 * 24 * 30,    // 30 days
            max_payload_bytes: 256 * 1024,         // 256 KiB
            max_pull_limit: 100,
            max_blob_bytes: 64 * 1024 * 1024, // 64 MiB
        }
    }
}

/// The wired-up set of ports plus configuration. Cheaply cloneable (everything is `Arc`).
///
/// A node opts into roles: every node runs the relay (`mailbox`); a node also running the blob
/// role has `blob` set (§13 item 4). Settlement is added when that phase lands (§13 item 8).
#[derive(Clone)]
pub struct Ctx {
    /// Relay/mailbox persistence.
    pub mailbox: Arc<dyn MailboxRepo>,
    /// Opaque media object store — `Some` only on nodes running the blob role.
    pub blob: Option<Arc<dyn BlobStore>>,
    /// Tuning knobs.
    pub config: CoreConfig,
}
