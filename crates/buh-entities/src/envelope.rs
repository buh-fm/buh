//! Envelope domain types.
//!
//! An envelope is a small, opaque, sealed ciphertext blob deposited into a queue. The relay
//! stores the bytes verbatim and never inspects them. Large media never travels here — only
//! a `{content key + blob locator}` does, folded into the sealed payload by the client
//! (`doc/design.md` §3.2).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ids::EnvelopeId;
use crate::queue::QueueId;

/// An envelope to be appended to a queue, as assembled by the relay handler.
#[derive(Debug, Clone)]
pub struct NewEnvelope {
    /// Opaque sealed ciphertext. The relay stores this verbatim.
    pub payload: Vec<u8>,
    /// Requested time-to-live in seconds (clamped to node policy by core).
    pub ttl_seconds: i64,
}

/// An envelope as stored and served back to a pulling client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEnvelope {
    /// Client-facing handle, used to acknowledge delivery.
    pub envelope_id: EnvelopeId,
    /// Opaque sealed ciphertext.
    #[serde(with = "crate::b64")]
    pub payload: Vec<u8>,
    /// When the relay received the envelope.
    pub received_at: DateTime<Utc>,
    /// When the envelope expires and becomes eligible for sweeping.
    pub expires_at: DateTime<Utc>,
}

/// A delivery receipt: the record that a queue's envelope was pulled (acknowledged).
///
/// This is the entire delivery-signal surface the relay exposes — "someone pulled envelope X
/// from queue Y at time T" — and is the basis for the fair-exchange work deferred to
/// `doc/design.md` §9.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// The queue the envelope belonged to.
    pub queue_id: QueueId,
    /// The acknowledged envelope.
    pub envelope_id: EnvelopeId,
    /// When the pull was acknowledged.
    pub pulled_at: DateTime<Utc>,
}
