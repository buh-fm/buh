//! Relay HTTP handlers.
//!
//! Sealed-sender semantics: there is no sender authentication. Possession of the `queue_id`
//! (the path segment) is the entire capability — the relay never learns who pushed an
//! envelope, only that an opaque queue received one and, later, that someone pulled it.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};

use buh_core::mailbox;
use buh_entities::{
    AckAccepted, EnvelopeAccepted, EnvelopeId, PullResponse, PushEnvelope, QueueId,
};

use crate::error::ApiError;
use crate::state::AppState;

/// Liveness probe.
pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
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
