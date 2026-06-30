//! The loopback admin API manages peer trust on a running node and updates the live trust
//! snapshot the TLS verifiers read — without a restart (`doc/design.md` §5.1).
//!
//! This is the fix for Turso's exclusive datastore lock: `buh-cli` can no longer open the DB while
//! the daemon holds it, so trust management goes through the daemon here instead.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt; // oneshot

use buh_api::admin::{AdminState, admin_router};
use buh_api::tls::TrustStore;
use buh_core::NodePki;
use buh_data::{DataStack, RcgenNodeCa, TursoPeerTrust};

/// Build an admin router over an in-memory registry plus a fresh trust snapshot; return all three.
async fn harness() -> (axum::Router, TrustStore, Arc<dyn NodePki>) {
    let stack = DataStack::connect(":memory:", buh_core::CoreConfig::default())
        .await
        .unwrap();
    stack.migrate().await.unwrap();

    let dir = tempfile::tempdir().unwrap();
    let pki: Arc<dyn NodePki> = Arc::new(
        RcgenNodeCa::load_or_init(dir.path(), vec!["node".into()], Duration::from_secs(3600))
            .unwrap(),
    );
    std::mem::forget(dir);

    let registry = Arc::new(TursoPeerTrust::new(stack.db.clone()));
    let trust = TrustStore::new();
    let router = admin_router(AdminState {
        registry,
        trust: trust.clone(),
        pki: pki.clone(),
    });
    (router, trust, pki)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn trust_then_distrust_updates_the_live_snapshot() {
    let (app, trust, _pki) = harness().await;
    let fp = "ab".repeat(32);

    assert!(!trust.contains(&fp), "starts untrusted");

    // POST /admin/peers trusts the CA.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/admin/peers")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "ca_fingerprint": fp, "note": "peer one" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // The live snapshot the verifiers read reflects it immediately — no restart.
    assert!(trust.contains(&fp), "live trust updated after POST");

    // GET /admin/peers lists it.
    let resp = app
        .clone()
        .oneshot(Request::get("/admin/peers").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["peers"].as_array().unwrap().len(), 1);
    assert_eq!(body["peers"][0]["ca_fingerprint"], fp);

    // DELETE removes it and refreshes the snapshot.
    let resp = app
        .clone()
        .oneshot(
            Request::delete(format!("/admin/peers/{fp}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["removed"], json!(true));
    assert!(!trust.contains(&fp), "live trust cleared after DELETE");
}

#[tokio::test]
async fn info_reports_the_node_ca_fingerprint() {
    let (app, _trust, pki) = harness().await;
    let resp = app
        .oneshot(Request::get("/admin/info").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["ca_fingerprint"], pki.ca_fingerprint());
    assert_eq!(body["trusted_peers"], json!(0));
}

#[tokio::test]
async fn fingerprint_is_normalized_through_the_api() {
    let (app, trust, _pki) = harness().await;
    // Operator pastes a colon-separated, upper-case fingerprint.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/admin/peers")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "ca_fingerprint": "AA:BB:CC" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(trust.contains("aabbcc"), "stored/applied in canonical form");
}
