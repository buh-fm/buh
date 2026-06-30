//! Blob-role HTTP round-trip: a client uploads opaque ciphertext and pulls it back
//! byte-identical through the real router (`doc/design.md` §3.2). The node is blind — it stores
//! and returns bytes it cannot read — and a node without the blob role answers `501`.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt; // for `oneshot`

use buh_api::router;
use buh_api::state::AppState;
use buh_core::CoreConfig;
use buh_data::DataStack;

/// Build a migrated node router. When `blob` is set the node runs the blob role over a temp
/// directory; `max_blob_bytes` bounds the accepted size.
async fn test_app(blob: bool, max_blob_bytes: usize) -> axum::Router {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("relay-test.db");
    let blob_root = dir.path().join("blobs");
    // Keep the tempdir alive for the run; the OS reclaims it on exit.
    std::mem::forget(dir);

    let config = CoreConfig {
        max_blob_bytes,
        ..CoreConfig::default()
    };
    let mut stack = DataStack::connect(db_path.to_str().unwrap(), config)
        .await
        .expect("connect datastore");
    stack.migrate().await.expect("migrate");
    if blob {
        stack = stack.with_fs_blob(blob_root);
    }

    let state = AppState {
        ctx: stack.ctx.clone(),
        max_wait: Duration::from_secs(1),
    };
    router(state)
}

fn put(uri: &str, body: &[u8]) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/octet-stream")
        .body(Body::from(body.to_vec()))
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn blob_put_get_roundtrip() {
    let app = test_app(true, 64 * 1024).await;
    // Opaque ciphertext, as produced client-side by buh-crypto's media sealing.
    let ciphertext = b"\x00\x01\xde\xad\xbe\xef sealed media bytes the node cannot read";
    let uri = "/v1/blob/media/aa/bb/object-key";

    let resp = app.clone().oneshot(put(uri, ciphertext)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app.clone().oneshot(get(uri)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/octet-stream")
    );
    let got = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(got.as_ref(), ciphertext, "blob survives the node verbatim");
}

#[tokio::test]
async fn missing_blob_is_not_found() {
    let app = test_app(true, 64 * 1024).await;
    let resp = app.oneshot(get("/v1/blob/media/absent")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oversize_blob_is_rejected() {
    // Core clamps to max_blob_bytes (8) before the much larger body-limit layer triggers.
    let app = test_app(true, 8).await;
    let resp = app
        .oneshot(put(
            "/v1/blob/media/k",
            b"this is far more than eight bytes",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn empty_blob_is_rejected() {
    let app = test_app(true, 64 * 1024).await;
    let resp = app.oneshot(put("/v1/blob/media/k", b"")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn blob_role_disabled_is_not_implemented() {
    let app = test_app(false, 64 * 1024).await;

    let resp = app
        .clone()
        .oneshot(put("/v1/blob/media/k", b"x"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

    let resp = app.oneshot(get("/v1/blob/media/k")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}
