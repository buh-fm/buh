//! Validation errors for constructing domain values.

use thiserror::Error;

/// Errors raised when validating or constructing domain values.
///
/// These are pure validation failures with no I/O involved; `buh-core` wraps them into its
/// own error type at the business-logic boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EntityError {
    /// A queue id was not exactly 32 bytes (after hex decoding).
    #[error("invalid queue id: {0}")]
    InvalidQueueId(String),
    /// A TTL was outside the acceptable range.
    #[error("invalid ttl: {0}")]
    InvalidTtl(&'static str),
    /// An envelope payload was empty or exceeded the size limit.
    #[error("invalid payload: {0}")]
    InvalidPayload(&'static str),
    /// A base64 field could not be decoded.
    #[error("invalid base64: {0}")]
    InvalidBase64(String),
    /// A required field was empty.
    #[error("field must not be empty: {0}")]
    Empty(&'static str),
}
