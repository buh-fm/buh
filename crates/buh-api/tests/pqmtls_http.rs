//! A real HTTP request driven through the PQ-mTLS serve loop (`buh_api::serve::serve_pqmtls`).
//!
//! The hermetic `pqmtls_handshake` test covers the TLS trust decision in isolation; this one
//! exercises the whole ingress path end to end: a trusted client completes the X25519MLKEM768
//! mutual handshake and gets a `200` from `GET /v1/health` (including the node's advertised CA
//! fingerprint), while a client whose CA the node does not trust is refused at the transport.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;

use rustls::pki_types::ServerName;

use buh_api::router::router;
use buh_api::serve::serve_pqmtls;
use buh_api::state::AppState;
use buh_api::tls::{NodeTls, TrustStore};
use buh_core::{CoreConfig, NodePki, PeerTrustRegistry};
use buh_data::{DataStack, RcgenNodeCa};

/// A node CA in a fresh (leaked) temp dir.
fn node_ca() -> Arc<dyn NodePki> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    std::mem::forget(dir);
    Arc::new(
        RcgenNodeCa::load_or_init(path, vec!["node".to_string()], Duration::from_secs(3600))
            .expect("init node CA"),
    )
}

/// A migrated in-memory data stack whose PKI is `server_ca`, with its peer-trust registry seeded
/// to trust each fingerprint in `trusted`.
async fn server_stack(server_ca: Arc<dyn NodePki>, trusted: &[String]) -> DataStack {
    let mut stack = DataStack::connect(":memory:", CoreConfig::default())
        .await
        .expect("connect");
    stack.migrate().await.expect("migrate");
    // Inject the prepared CA + the Turso-backed trust registry as the node's PKI ports.
    stack.ctx.pki = Some(server_ca);
    let registry = Arc::new(buh_data::TursoPeerTrust::new(stack.db.clone()));
    for fp in trusted {
        registry.trust(fp, None).await.expect("trust peer");
    }
    stack.ctx.peer_trust = Some(registry);
    stack
}

/// Start `serve_pqmtls` on an ephemeral port; returns the bound address and a shutdown handle.
async fn spawn_server(stack: &DataStack) -> (std::net::SocketAddr, oneshot::Sender<()>) {
    let pki = stack.ctx.pki.clone().unwrap();
    let registry = stack.ctx.peer_trust.clone().unwrap();
    let app = router(AppState {
        ctx: stack.ctx.clone(),
        max_wait: Duration::from_secs(1),
    });
    let node_tls = NodeTls::new(pki, TrustStore::new()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = serve_pqmtls(
            app,
            listener,
            node_tls,
            registry,
            Duration::from_secs(3600),
            async move {
                let _ = rx.await;
            },
        )
        .await;
    });
    (addr, tx)
}

/// Make `GET /v1/health` over PQ-mTLS using `client_tls`, returning the raw HTTP/1.1 response.
async fn get_health(addr: std::net::SocketAddr, client_tls: &NodeTls) -> Result<String, String> {
    let connector = TlsConnector::from(Arc::new(
        client_tls.client_config().map_err(|e| e.to_string())?,
    ));
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let name = ServerName::try_from("node").unwrap();
    let mut tls = connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())?;
    tls.write_all(b"GET /v1/health HTTP/1.1\r\nHost: node\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[tokio::test]
async fn trusted_client_gets_health_with_ca_fingerprint() {
    let server = node_ca();
    let client = node_ca();
    let server_fp = server.ca_fingerprint().to_string();
    let client_fp = client.ca_fingerprint().to_string();

    // The node trusts the client's CA; the client pins the node's CA.
    let stack = server_stack(server, &[client_fp]).await;
    let (addr, _shutdown) = spawn_server(&stack).await;
    let client_tls =
        NodeTls::new(client, TrustStore::from_fingerprints([server_fp.clone()])).unwrap();

    let response = get_health(addr, &client_tls)
        .await
        .expect("request should succeed");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got: {response}"
    );
    assert!(
        response.contains(&server_fp),
        "health body should advertise the node CA fingerprint {server_fp}"
    );
}

#[tokio::test]
async fn untrusted_client_is_refused_at_the_transport() {
    let server = node_ca();
    let client = node_ca();
    let server_fp = server.ca_fingerprint().to_string();

    // The node trusts NOBODY; the client still pins the node's CA so it would accept the server.
    let stack = server_stack(server, &[]).await;
    let (addr, _shutdown) = spawn_server(&stack).await;
    let client_tls = NodeTls::new(client, TrustStore::from_fingerprints([server_fp])).unwrap();

    let result = get_health(addr, &client_tls).await;
    assert!(
        result.is_err(),
        "untrusted client must be refused, got: {result:?}"
    );
}
