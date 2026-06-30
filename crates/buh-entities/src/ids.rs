//! UUID-backed identifier newtypes.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identifies a single stored envelope within a queue.
///
/// Client-facing handle returned on push and used to acknowledge delivery. It is meaningless
/// across queues and carries no information about sender or recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnvelopeId(pub Uuid);

impl EnvelopeId {
    /// Generate a fresh random (v4) identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// The underlying [`Uuid`].
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for EnvelopeId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for EnvelopeId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

impl From<EnvelopeId> for Uuid {
    fn from(id: EnvelopeId) -> Self {
        id.0
    }
}

impl std::fmt::Display for EnvelopeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for EnvelopeId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}
