//! The opaque queue identifier — the entire addressing surface a relay sees.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::EntityError;

/// Length of a [`QueueId`] in bytes.
pub const QUEUE_ID_LEN: usize = 32;

/// A queue identifier: 32 opaque bytes that act as an unforgeable capability.
///
/// Possession of a `QueueId` is the only authorization needed to push to (or pull from) that
/// queue — this is the sealed-sender / blind-relay model. The relay never learns who owns a
/// queue, never correlates two queues, and cannot enumerate a social graph from them
/// (`doc/design.md` §3.1). Queues are unidirectional (one per contact-direction), so the two
/// halves of a conversation are uncorrelatable at the relay.
///
/// The wire/string form is lowercase hex (64 characters).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct QueueId([u8; QUEUE_ID_LEN]);

impl QueueId {
    /// Construct from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; QUEUE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; QUEUE_ID_LEN] {
        &self.0
    }

    /// Parse from a byte slice, validating the length.
    pub fn from_slice(slice: &[u8]) -> Result<Self, EntityError> {
        let arr: [u8; QUEUE_ID_LEN] = slice.try_into().map_err(|_| {
            EntityError::InvalidQueueId(format!(
                "expected {QUEUE_ID_LEN} bytes, got {}",
                slice.len()
            ))
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for QueueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for QueueId {
    type Err = EntityError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)
            .map_err(|e| EntityError::InvalidQueueId(format!("not valid hex: {e}")))?;
        Self::from_slice(&bytes)
    }
}

impl TryFrom<String> for QueueId {
    type Error = EntityError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<QueueId> for String {
    fn from(q: QueueId) -> Self {
        q.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let q = QueueId::from_bytes([0x11; QUEUE_ID_LEN]);
        let s = q.to_string();
        assert_eq!(s.len(), 64);
        assert_eq!(s.parse::<QueueId>().unwrap(), q);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!("aabb".parse::<QueueId>().is_err());
        assert!(QueueId::from_slice(&[0u8; 31]).is_err());
        assert!(QueueId::from_slice(&[0u8; 33]).is_err());
    }

    #[test]
    fn rejects_non_hex() {
        assert!("zz".repeat(32).parse::<QueueId>().is_err());
    }
}
