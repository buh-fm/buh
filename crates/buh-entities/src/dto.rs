//! Request/response DTOs for the relay HTTP API (`/v1`).
//!
//! These are shared with clients. Binary payloads are carried as base64 strings.

use serde::{Deserialize, Serialize};

use crate::envelope::StoredEnvelope;
use crate::ids::EnvelopeId;

/// Push request body: a sealed envelope plus a requested TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushEnvelope {
    /// Opaque sealed ciphertext (base64).
    #[serde(with = "crate::b64")]
    pub payload: Vec<u8>,
    /// Requested time-to-live in seconds. Clamped to node policy server-side.
    pub ttl_seconds: i64,
}

/// Push response: the assigned envelope id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeAccepted {
    /// The handle the client uses to acknowledge delivery later.
    pub envelope_id: EnvelopeId,
}

/// Pull response: a batch of live envelopes for the queue, oldest first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    /// The envelopes returned (may be empty).
    pub envelopes: Vec<StoredEnvelope>,
}

/// Acknowledgement response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckAccepted {
    /// Whether the envelope was found and acknowledged (`false` if already gone).
    pub acknowledged: bool,
}
