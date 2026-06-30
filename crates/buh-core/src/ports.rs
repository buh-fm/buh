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

/// A freshly issued node leaf certificate plus its private key, DER-encoded.
///
/// Returned by [`NodePki::issue_leaf`]; the transport layer (`buh-api`) turns it into a rustls
/// signing key. Core stays free of rustls/rcgen types — only opaque DER bytes cross this seam.
#[derive(Clone)]
pub struct NodeLeaf {
    /// The certificate chain, **leaf first then the issuing node CA**, each DER-encoded. Peers
    /// pin the CA (the last element) by fingerprint; the leaf is verified to chain to it.
    pub chain_der: Vec<Vec<u8>>,
    /// The leaf private key, PKCS#8 DER.
    pub private_key_der: Vec<u8>,
    /// Leaf expiry as epoch milliseconds — drives the in-process rotation timer.
    pub not_after_ms: i64,
}

/// A node's own PKI: a long-lived CA whose fingerprint peers and clients pin, and the
/// short-lived leaves it issues for the PQ-mTLS listener (`doc/design.md` §5.1 — the
/// decentralised per-node-CA deviation).
///
/// There is **no central PKI and no step-ca**: every node is its own root of trust. Trust is
/// established peer-to-peer by pinning a CA fingerprint (see [`PeerTrustRegistry`]), never via a
/// shared root. Implemented by `buh-data`'s `RcgenNodeCa`.
pub trait NodePki: Send + Sync {
    /// The CA fingerprint clients pin: **lowercase hex SHA-256 of the CA certificate DER**.
    fn ca_fingerprint(&self) -> &str;

    /// The node CA certificate, DER-encoded (distributed out of band / carried in invites).
    fn ca_cert_der(&self) -> &[u8];

    /// Issue a fresh short-lived leaf signed by the CA. Called once on startup and again on each
    /// tick of the in-process rotation timer.
    fn issue_leaf(&self) -> Result<NodeLeaf, CoreError>;
}

/// One trusted peer-CA entry.
#[derive(Debug, Clone)]
pub struct TrustedPeer {
    /// The pinned CA fingerprint (lowercase hex SHA-256 of the CA cert DER).
    pub ca_fingerprint: String,
    /// Optional operator note (who/what this CA belongs to).
    pub note: Option<String>,
    /// When trust was recorded.
    pub trusted_at: DateTime<Utc>,
}

/// Per-CA peer trust registry: the set of peer-node CA fingerprints this node will accept on a
/// PQ-mTLS handshake. Backed by the embedded Turso DB (`doc/design.md` §5.1, Node trust model).
///
/// Pinning is **per CA, not a shared root**: a node trusts exactly the CAs it has been told to,
/// and a peer is refused the instant its CA is distrusted. The transport layer reads a cached
/// snapshot of this set inside its (synchronous) certificate verifiers.
#[async_trait]
pub trait PeerTrustRegistry: Send + Sync {
    /// Trust a peer CA by fingerprint (idempotent; updates the note if already present).
    async fn trust(&self, ca_fingerprint: &str, note: Option<&str>) -> Result<(), CoreError>;

    /// Remove trust for a peer CA. Returns `false` if it was not trusted.
    async fn distrust(&self, ca_fingerprint: &str) -> Result<bool, CoreError>;

    /// Whether a CA fingerprint is currently trusted.
    async fn is_trusted(&self, ca_fingerprint: &str) -> Result<bool, CoreError>;

    /// All trusted peer CAs, newest first.
    async fn list(&self) -> Result<Vec<TrustedPeer>, CoreError>;
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
