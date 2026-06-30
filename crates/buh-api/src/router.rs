//! Route table.

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post, put};
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::state::AppState;

/// Build the node application router.
///
/// Every node mounts the relay role. The blob routes are always mounted but answer `501` unless
/// the node runs the blob role (`Ctx.blob` is set); the blob `PUT` body limit follows the
/// node's `max_blob_bytes`, while the small relay/JSON routes keep axum's default limit. The
/// blob key is a wildcard so locators may nest (`bucket/aa/bb`).
pub fn router(state: AppState) -> Router {
    // A little slack over the raw ciphertext limit for the encoding overhead.
    let blob_limit = state.ctx.config.max_blob_bytes.saturating_add(64 * 1024);

    let blob = Router::new()
        .route(
            "/v1/blob/{bucket}/{*key}",
            put(handlers::blob_put).get(handlers::blob_get),
        )
        .layer(DefaultBodyLimit::max(blob_limit));

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
        .merge(blob)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
