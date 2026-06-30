//! The dependency-injection context that bundles the port implementations.
//!
//! Binaries construct a [`Ctx`] once at startup from the `data` adapters and pass `&Ctx` to
//! the business-logic functions. Tests construct one from in-memory fakes.

use std::sync::Arc;

use crate::ports::MailboxRepo;

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
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: 60 * 60 * 24 * 7, // 7 days
            max_ttl_seconds: 60 * 60 * 24 * 30,    // 30 days
            max_payload_bytes: 256 * 1024,         // 256 KiB
            max_pull_limit: 100,
        }
    }
}

/// The wired-up set of ports plus configuration. Cheaply cloneable (everything is `Arc`).
///
/// In Milestone 1 a node runs the relay role only; blob and settlement ports are added to the
/// context as their phases land (§13 items 4 and 8).
#[derive(Clone)]
pub struct Ctx {
    /// Relay/mailbox persistence.
    pub mailbox: Arc<dyn MailboxRepo>,
    /// Tuning knobs.
    pub config: CoreConfig,
}
