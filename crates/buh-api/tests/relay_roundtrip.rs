//! End-to-end relay round-trip: two clients exchange one sealed envelope through a blind
//! relay queue, driven through the real HTTP router. This is the Milestone-1 "done" test
//! (`doc/design.md` §13 item 1) and the primary guard for the hand-written Turso SQL (we
//! forgo sqlx compile-time checks).
//!
//! Throughout, the node stays blind: it sees only that an opaque queue received an envelope
//! and, later, that someone pulled it.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt; // for `oneshot`

use buh_api::router;
use buh_api::state::AppState;
use buh_core::CoreConfig;
use buh_data::DataStack;

/// Build a migrated, in-memory relay router for the test.
async fn test_app() -> (axum::Router, DataStack) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relay-test.db");
    // Keep the tempdir alive for the duration by leaking it into the path string; the OS
    // cleans up on process exit. (Simplicity over teardown for a single-run test.)
    std::mem::forget(dir);

    let stack = DataStack::connect(db_path.to_str().unwrap(), CoreConfig::default())
        .await
        .expect("connect datastore");
    stack.migrate().await.expect("migrate");

    let state = AppState {
        ctx: stack.ctx.clone(),
        max_wait: Duration::from_secs(1),
    };
    (router(state), stack)
}

/// Collect a response body into JSON.
async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn push_pull_ack_roundtrip() {
    let (app, stack) = test_app().await;

    // A queue is just 32 opaque bytes (hex in the path). Bob handed Alice this queue.
    let queue_hex = "11".repeat(32);
    let plaintext = b"sealed ciphertext bytes (opaque to the node)";
    let payload_b64 = STANDARD.encode(plaintext);

    // 1. Alice pushes a sealed envelope to Bob's queue.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/queue/{queue_hex}/envelopes"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "payload": payload_b64, "ttl_seconds": 3600 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let envelope_id = body_json(resp).await["envelope_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Bob pulls his queue and gets the envelope back, byte-identical.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/queue/{queue_hex}/envelopes"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let pulled = body_json(resp).await;
    let envelopes = pulled["envelopes"].as_array().unwrap();
    assert_eq!(envelopes.len(), 1, "exactly one envelope queued");
    assert_eq!(envelopes[0]["envelope_id"].as_str().unwrap(), envelope_id);
    let got = STANDARD
        .decode(envelopes[0]["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(got, plaintext, "payload survives the relay verbatim");

    // 3. Bob acknowledges delivery.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/queue/{queue_hex}/envelopes/{envelope_id}/ack"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["acknowledged"], json!(true));

    // 4. A second pull is now empty.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/queue/{queue_hex}/envelopes"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        body_json(resp).await["envelopes"]
            .as_array()
            .unwrap()
            .is_empty(),
        "acked envelope no longer delivered"
    );

    // 5. A delivery receipt was recorded — the only delivery signal the relay exposes.
    let conn = stack.db.connect().unwrap();
    let mut rows = conn
        .query("SELECT COUNT(*) FROM delivery_receipts", ())
        .await
        .unwrap();
    let row = rows.next().await.unwrap().unwrap();
    let count = match row.get_value(0).unwrap() {
        turso::Value::Integer(n) => n,
        other => panic!("unexpected count type: {other:?}"),
    };
    assert_eq!(count, 1, "exactly one delivery receipt");
}

#[tokio::test]
async fn ack_unknown_envelope_is_false() {
    let (app, _stack) = test_app().await;
    let queue_hex = "22".repeat(32);
    let bogus = uuid_like();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/queue/{queue_hex}/envelopes/{bogus}/ack"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["acknowledged"], json!(false));
}

#[tokio::test]
async fn bad_queue_id_is_rejected() {
    let (app, _stack) = test_app().await;
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/queue/not-hex/envelopes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// A syntactically valid (but unused) UUID string.
fn uuid_like() -> String {
    "00000000-0000-4000-8000-000000000000".to_string()
}
