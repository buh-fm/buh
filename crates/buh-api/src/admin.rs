//! Loopback-only operator admin API (`doc/design.md` §5.1, the per-node trust model).
//!
//! Turso locks the datastore exclusively per process, so `buh-cli` cannot open the DB while the
//! daemon holds it. The daemon therefore owns the DB and exposes peer-trust management here, on a
//! **separate loopback listener** — never the PQ-mTLS edge. Mutations are written to the registry
//! **and** applied to the live [`TrustStore`] the certificate verifiers read, so a trust change
//! takes effect on the next handshake without a restart.
//!
//! There is no auth on this surface: it is bound to loopback, and anyone with loopback access on
//! the node host is already privileged. Do not expose it beyond `127.0.0.1`/a Unix socket.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};

use buh_core::{NodePki, PeerTrustRegistry};

use crate::error::ApiError;
use crate::tls::TrustStore;

/// State shared by the admin handlers: the durable registry, the live trust snapshot the verifiers
/// read, and this node's PKI (to report its own fingerprint).
#[derive(Clone)]
pub struct AdminState {
    /// Durable peer-CA trust registry (Turso-backed).
    pub registry: Arc<dyn PeerTrustRegistry>,
    /// The live, in-memory trust snapshot used by the TLS verifiers.
    pub trust: TrustStore,
    /// This node's own PKI (for `GET /admin/info`).
    pub pki: Arc<dyn NodePki>,
}

/// Build the loopback admin router.
pub fn admin_router(state: AdminState) -> Router {
    Router::new()
        .route("/admin/info", get(info))
        .route("/admin/peers", get(list_peers).post(trust_peer))
        .route("/admin/peers/{ca_fp}", axum::routing::delete(distrust_peer))
        // belt-and-braces alias so a POST-only client can still distrust
        .route("/admin/peers/{ca_fp}/distrust", post(distrust_peer))
        .with_state(state)
}

/// `GET /admin/info` — this node's CA fingerprint and trusted-peer count.
async fn info(State(s): State<AdminState>) -> Result<Json<Value>, ApiError> {
    let peers = s.registry.list().await?;
    Ok(Json(json!({
        "ca_fingerprint": s.pki.ca_fingerprint(),
        "trusted_peers": peers.len(),
    })))
}

/// `GET /admin/peers` — list trusted peer CAs.
async fn list_peers(State(s): State<AdminState>) -> Result<Json<Value>, ApiError> {
    let peers = s.registry.list().await?;
    let peers: Vec<Value> = peers
        .into_iter()
        .map(|p| {
            json!({
                "ca_fingerprint": p.ca_fingerprint,
                "note": p.note,
                "trusted_at_ms": p.trusted_at.timestamp_millis(),
            })
        })
        .collect();
    Ok(Json(json!({ "peers": peers })))
}

/// Body of `POST /admin/peers`.
#[derive(Debug, Deserialize)]
struct TrustRequest {
    /// The peer CA fingerprint to pin (normalised by the registry).
    ca_fingerprint: String,
    /// Optional operator note.
    #[serde(default)]
    note: Option<String>,
}

/// `POST /admin/peers` — trust a peer CA, then refresh the live snapshot.
async fn trust_peer(
    State(s): State<AdminState>,
    Json(req): Json<TrustRequest>,
) -> Result<Json<Value>, ApiError> {
    s.registry
        .trust(&req.ca_fingerprint, req.note.as_deref())
        .await?;
    refresh_live(&s).await?;
    Ok(Json(json!({ "trusted": req.ca_fingerprint })))
}

/// `DELETE /admin/peers/{ca_fp}` — distrust a peer CA, then refresh the live snapshot.
async fn distrust_peer(
    State(s): State<AdminState>,
    Path(ca_fp): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let removed = s.registry.distrust(&ca_fp).await?;
    refresh_live(&s).await?;
    Ok(Json(json!({ "removed": removed })))
}

/// Re-read the registry and replace the live trust snapshot, so the change is enforced on the next
/// handshake without waiting for the rotation timer.
async fn refresh_live(s: &AdminState) -> Result<(), ApiError> {
    let peers = s.registry.list().await?;
    s.trust.replace(peers.into_iter().map(|p| p.ca_fingerprint));
    Ok(())
}
