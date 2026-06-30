//! Relay HTTP handlers.
//!
//! Sealed-sender semantics: there is no sender authentication. Possession of the `queue_id`
//! (the path segment) is the entire capability — the relay never learns who pushed an
//! envelope, only that an opaque queue received one and, later, that someone pulled it.

use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use buh_core::{blob, mailbox};
use buh_entities::{
    AckAccepted, EnvelopeAccepted, EnvelopeId, PullResponse, PushEnvelope, QueueId,
};

use crate::error::ApiError;
use crate::state::AppState;

/// Liveness probe. On a PQ-mTLS node it also advertises the node's CA fingerprint — the public
/// value clients pin (`doc/design.md` §5.1). Exposing it is safe (it is the node's public
/// identity) and lets a client confirm the fingerprint carried in an invite matches the node it
/// is actually talking to.
pub async fn health(State(state): State<AppState>) -> Json<Value> {
    match state.ctx.pki.as_ref() {
        Some(pki) => Json(json!({ "status": "ok", "ca_fingerprint": pki.ca_fingerprint() })),
        None => Json(json!({ "status": "ok" })),
    }
}

/// `POST /v1/queue/{queue_id}/envelopes` — push a sealed envelope.
pub async fn push(
    State(state): State<AppState>,
    Path(queue_hex): Path<String>,
    Json(body): Json<PushEnvelope>,
) -> Result<Json<EnvelopeAccepted>, ApiError> {
    let queue_id: QueueId = queue_hex.parse()?;
    let envelope_id = mailbox::push(&state.ctx, &queue_id, body).await?;
    Ok(Json(EnvelopeAccepted { envelope_id }))
}

/// Query parameters for a pull.
#[derive(Debug, Deserialize)]
pub struct PullParams {
    /// Maximum envelopes to return (clamped to node policy).
    #[serde(default)]
    pub limit: Option<i64>,
    /// Seconds to long-poll if the queue is currently empty (clamped to node policy).
    #[serde(default)]
    pub wait: Option<u64>,
}

/// `GET /v1/queue/{queue_id}/envelopes` — pull live envelopes, oldest first. If empty and
/// `wait` is set, block up to that many seconds for an arrival before returning.
pub async fn pull(
    State(state): State<AppState>,
    Path(queue_hex): Path<String>,
    Query(params): Query<PullParams>,
) -> Result<Json<PullResponse>, ApiError> {
    let queue_id: QueueId = queue_hex.parse()?;
    let limit = params.limit.unwrap_or(state.ctx.config.max_pull_limit);

    let mut envelopes = mailbox::pull(&state.ctx, &queue_id, limit).await?;

    if envelopes.is_empty() {
        if let Some(wait) = params.wait {
            if wait > 0 {
                let wait = Duration::from_secs(wait).min(state.max_wait);
                let woken = state.ctx.mailbox.wait_for_envelope(&queue_id, wait).await?;
                if woken {
                    envelopes = mailbox::pull(&state.ctx, &queue_id, limit).await?;
                }
            }
        }
    }

    Ok(Json(PullResponse { envelopes }))
}

/// `POST /v1/queue/{queue_id}/envelopes/{envelope_id}/ack` — acknowledge delivery.
pub async fn ack(
    State(state): State<AppState>,
    Path((queue_hex, envelope_id)): Path<(String, String)>,
) -> Result<Json<AckAccepted>, ApiError> {
    let queue_id: QueueId = queue_hex.parse()?;
    let envelope_id: EnvelopeId = envelope_id
        .parse()
        .map_err(|_| buh_entities::EntityError::Empty("envelope_id"))?;
    let acknowledged = mailbox::ack(&state.ctx, &queue_id, envelope_id).await?;
    Ok(Json(AckAccepted { acknowledged }))
}

/// `PUT /v1/blob/{bucket}/{key}` — store opaque, client-encrypted ciphertext. The node holds
/// bytes it cannot read; possession of the locator is the entire capability. `501` if this node
/// does not run the blob role. The body size is bounded by the route's request-body limit.
pub async fn blob_put(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    blob::put(&state.ctx, &bucket, &key, body.to_vec()).await?;
    Ok(StatusCode::CREATED)
}

/// `GET /v1/blob/{bucket}/{key}` — fetch the opaque ciphertext. `404` if absent, `501` if this
/// node does not run the blob role.
pub async fn blob_get(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let bytes = blob::get(&state.ctx, &bucket, &key).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response())
}
