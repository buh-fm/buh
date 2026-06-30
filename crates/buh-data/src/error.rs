//! Mapping datastore failures into [`buh_core::CoreError`].

use buh_core::CoreError;

/// Map any displayable datastore error into a repository error. Generic over the error type
/// so we don't couple to the exact `turso` error name.
pub(crate) fn repo<E: std::fmt::Display>(e: E) -> CoreError {
    CoreError::Repo(e.to_string())
}
