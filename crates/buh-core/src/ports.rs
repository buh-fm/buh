//! Port traits: the seams that the `data` crate implements.
//!
//! Core logic depends only on these abstractions, never on `turso`, S3, or a chain SDK
//! directly. This keeps the (deliberately thin) relay logic unit-testable against in-memory
//! fakes and lets the storage and settlement implementations evolve independently.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use buh_entities::{
    Credit, DepositInstructions, DepositProof, EnvelopeId, NewEnvelope, Payout, QueueId,
    SolvencyProof, StoredEnvelope, TxRef,
};

use crate::error::CoreError;

/// The relay/mailbox persistence port.
///
/// The store keeps only `queue_id → envelope_refs`, TTL/expiry, and delivery receipts — no
/// identities, no cross-queue correlation (`doc/design.md` §3.1). `queue_id` is the
/// capability; no sender identity is ever passed in or stored.
#[async_trait]
pub trait MailboxRepo: Send + Sync {
    /// Append an envelope to a queue. Returns the new envelope id.
    async fn push(
        &self,
        queue_id: &QueueId,
        envelope: &NewEnvelope,
    ) -> Result<EnvelopeId, CoreError>;

    /// Pull up to `limit` live (unexpired, unacknowledged) envelopes for a queue, oldest
    /// first. Does not delete — deletion happens on [`MailboxRepo::ack`].
    async fn pull(&self, queue_id: &QueueId, limit: i64) -> Result<Vec<StoredEnvelope>, CoreError>;

    /// Acknowledge delivery of an envelope: record a receipt and remove it from the live set.
    /// Returns `false` if the envelope was not present (already acked or expired).
    async fn ack(
        &self,
        queue_id: &QueueId,
        envelope_id: EnvelopeId,
        at: DateTime<Utc>,
    ) -> Result<bool, CoreError>;

    /// Delete expired envelopes (TTL sweep). Returns the number removed.
    async fn expire(&self, now: DateTime<Utc>) -> Result<u64, CoreError>;

    /// Block until an envelope is available for `queue_id`, or `timeout` elapses. Returns
    /// `true` if woken by an arrival, `false` on timeout. Served by an in-process notifier
    /// (a node is a single process — no cross-process `LISTEN/NOTIFY` needed).
    async fn wait_for_envelope(
        &self,
        queue_id: &QueueId,
        timeout: Duration,
    ) -> Result<bool, CoreError>;
}

/// Object store for opaque, client-encrypted media blobs (Phase 5).
///
/// A blob node holds bytes it cannot read: media is encrypted client-side under a per-file
/// content key before upload, and only `{content key + locator}` travels through the ratchet
/// envelope (`doc/design.md` §3.2). Provider-swappable: S3/MinIO or filesystem/ZFS.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Whether an object exists at `key` in `bucket`.
    async fn exists(&self, bucket: &str, key: &str) -> Result<bool, CoreError>;

    /// Store opaque ciphertext bytes at `key` in `bucket`.
    async fn put(&self, bucket: &str, key: &str, bytes: Vec<u8>) -> Result<(), CoreError>;

    /// Fetch the full object bytes.
    async fn get(&self, bucket: &str, key: &str) -> Result<Vec<u8>, CoreError>;

    /// Produce a short-lived URL for fetching the object directly.
    async fn presign_get(
        &self,
        bucket: &str,
        key: &str,
        ttl_seconds: u64,
    ) -> Result<String, CoreError>;
}

/// Edge settlement backend (Phase 7 / `doc/design.md` §8.5).
///
/// **The one component with no architectural opinion worth defending — pure value-in/value-out
/// plumbing.** Above this seam, every component speaks abstract service [`Credit`]s and has
/// never heard of a chain. `EthSettlement` / `SolSettlement` implement this; neither is in
/// core. Design for both, build exactly one — the test that the seam is right is that the
/// *second* backend is a weekend, not a rewrite.
#[async_trait]
pub trait SettlementBackend: Send + Sync {
    /// Quote deposit instructions for obtaining entitlement worth `value` at the edge.
    async fn onramp_quote(&self, value: Credit) -> Result<DepositInstructions, CoreError>;

    /// Confirm an edge deposit and mint the corresponding service entitlement.
    async fn confirm_deposit(&self, proof: DepositProof) -> Result<Credit, CoreError>;

    /// Pay a node runner at the edge for redeemed service credits.
    async fn payout(&self, redeemed: Credit, dest: Payout) -> Result<TxRef, CoreError>;

    /// Attest the backend's capacity to settle outstanding entitlement.
    async fn reserve_attestation(&self) -> Result<SolvencyProof, CoreError>;
}
