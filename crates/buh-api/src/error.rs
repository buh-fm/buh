//! API error type and its mapping onto HTTP status codes.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use buh_core::CoreError;
use buh_entities::EntityError;

/// Wraps a [`CoreError`] for rendering as an HTTP response.
pub struct ApiError(pub CoreError);

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> Self {
        Self(e)
    }
}

impl From<EntityError> for ApiError {
    fn from(e: EntityError) -> Self {
        Self(e.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self.0 {
            CoreError::NotFound => (StatusCode::NOT_FOUND, self.0.to_string()),
            CoreError::Validation(_) => (StatusCode::BAD_REQUEST, self.0.to_string()),
            CoreError::Conflict(_) => (StatusCode::CONFLICT, self.0.to_string()),
            CoreError::Unimplemented(_) => (StatusCode::NOT_IMPLEMENTED, self.0.to_string()),
            CoreError::Repo(_) | CoreError::Storage(_) | CoreError::Internal(_) => {
                // Don't leak internal detail to clients; log it instead.
                tracing::error!(error = %self.0, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal error".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
