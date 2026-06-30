//! Route table.

use axum::Router;
use axum::routing::{get, post};
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::state::AppState;

/// Build the relay application router.
///
/// In Milestone 1 only the relay role is mounted. Blob (Phase 5) and any browser-facing
/// surface attach here later.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(handlers::health))
        .route(
            "/v1/queue/{queue_id}/envelopes",
            post(handlers::push).get(handlers::pull),
        )
        .route(
            "/v1/queue/{queue_id}/envelopes/{envelope_id}/ack",
            post(handlers::ack),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
