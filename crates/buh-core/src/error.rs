//! The error type returned by business-logic functions and port traits.

use buh_entities::EntityError;
use thiserror::Error;

/// Errors produced by core logic and the data-access ports it depends on.
///
/// `buh-data` maps its storage failures into these variants; the API maps these onto HTTP
/// status codes.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A requested resource does not exist.
    #[error("not found")]
    NotFound,
    /// The operation conflicts with existing state.
    #[error("conflict: {0}")]
    Conflict(String),
    /// A domain value failed validation.
    #[error(transparent)]
    Validation(#[from] EntityError),
    /// The datastore / repository failed.
    #[error("repository error: {0}")]
    Repo(String),
    /// The object store failed.
    #[error("storage error: {0}")]
    Storage(String),
    /// The operation is not implemented (e.g. a stub settlement backend).
    #[error("not implemented: {0}")]
    Unimplemented(&'static str),
    /// An unexpected internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Convenience alias for results in this crate.
pub type CoreResult<T> = Result<T, CoreError>;
