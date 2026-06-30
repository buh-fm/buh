//! The crate-wide error type for buh-crypto.

use crate::wire::WireError;

/// Anything that can go wrong inside the client crypto core.
///
/// Deliberately coarse: a decryption/verification failure exposes *that* it failed but never
/// *why* (no padding-oracle / which-byte distinctions), and carries no secret material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// A wire frame failed to decode or validate.
    #[error(transparent)]
    Wire(#[from] WireError),

    /// AEAD open failed — wrong key, wrong nonce, tampered ciphertext, or tampered AAD.
    #[error("aead authentication failed")]
    Aead,

    /// An ML-DSA signature did not verify against the message and key.
    #[error("signature verification failed")]
    BadSignature,

    /// A key, signature, or other fixed-size field had the wrong length or structure.
    #[error("malformed {what}")]
    Malformed {
        /// What was being parsed (e.g. "identity public key").
        what: &'static str,
    },

    /// A ratchet operation could not proceed (no sending chain yet, too many skipped
    /// messages, …). Carries a static reason, never secret state.
    #[error("ratchet: {0}")]
    Ratchet(&'static str),
}

impl CryptoError {
    /// Construct a [`CryptoError::Malformed`] for `what`.
    #[must_use]
    pub fn malformed(what: &'static str) -> Self {
        Self::Malformed { what }
    }
}
