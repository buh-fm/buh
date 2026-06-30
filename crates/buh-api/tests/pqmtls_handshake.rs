//! Hermetic PQ-mTLS handshake between two in-process nodes (`doc/design.md` §5.1, Phase 6).
//!
//! No external CA, no network beyond loopback. Each node is its own CA; a handshake succeeds
//! only when **each side pins the other's CA fingerprint**, the key exchange is the post-quantum
//! X25519MLKEM768 hybrid, and a peer is refused the instant its CA is distrusted.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use rustls::NamedGroup;
use rustls::pki_types::ServerName;

use buh_api::tls::{NodeTls, TrustStore};
use buh_core::NodePki;
use buh_data::RcgenNodeCa;

/// Spin up a node CA in a fresh temp dir. The dir is leaked so the CA files outlive the call.
fn node_ca() -> Arc<dyn NodePki> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    std::mem::forget(dir);
    Arc::new(
        RcgenNodeCa::load_or_init(path, vec!["node".to_string()], Duration::from_secs(3600))
            .expect("init node CA"),
    )
}

/// Run a one-shot PQ-mTLS server with `server_tls`; it accepts a single connection, echoes one
/// byte, and reports back the negotiated key-exchange group (or `None` if the handshake failed).
async fn run_server(
    server_tls: NodeTls,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<Option<NamedGroup>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_tls.server_config().unwrap()));

    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.ok()?;
        let mut tls = acceptor.accept(stream).await.ok()?;
        let group = tls
            .get_ref()
            .1
            .negotiated_key_exchange_group()
            .map(|g| g.name());
        let mut buf = [0u8; 1];
        let _ = tls.read_exact(&mut buf).await;
        let _ = tls.write_all(b"!").await;
        let _ = tls.shutdown().await;
        group
    });

    (addr, handle)
}

/// Attempt a client handshake to `addr` with `client_tls`. On success returns the negotiated
/// key-exchange group; any handshake/verification failure is surfaced as `Err`.
async fn try_client(addr: std::net::SocketAddr, client_tls: NodeTls) -> Result<NamedGroup, String> {
    let connector = TlsConnector::from(Arc::new(
        client_tls.client_config().map_err(|e| e.to_string())?,
    ));
    let stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let name = ServerName::try_from("node").unwrap();
    let mut tls = connector
        .connect(name, stream)
        .await
        .map_err(|e| e.to_string())?;
    let group = tls
        .get_ref()
        .1
        .negotiated_key_exchange_group()
        .map(|g| g.name())
        .ok_or_else(|| "no kx group".to_string())?;
    tls.write_all(b"?").await.map_err(|e| e.to_string())?;
    let mut buf = [0u8; 1];
    tls.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(group)
}

#[tokio::test]
async fn handshake_succeeds_when_each_pins_the_other_and_uses_x25519mlkem768() {
    let a = node_ca();
    let b = node_ca();

    // A trusts B's CA; B trusts A's CA.
    let a_tls = NodeTls::new(
        a.clone(),
        TrustStore::from_fingerprints([b.ca_fingerprint().to_string()]),
    )
    .unwrap();
    let b_tls = NodeTls::new(
        b.clone(),
        TrustStore::from_fingerprints([a.ca_fingerprint().to_string()]),
    )
    .unwrap();

    let (addr, server) = run_server(a_tls).await;
    let client_group = try_client(addr, b_tls)
        .await
        .expect("handshake should succeed");
    let server_group = server
        .await
        .unwrap()
        .expect("server handshake should succeed");

    assert_eq!(
        client_group,
        NamedGroup::X25519MLKEM768,
        "client kx must be PQ hybrid"
    );
    assert_eq!(
        server_group,
        NamedGroup::X25519MLKEM768,
        "server kx must be PQ hybrid"
    );
}

#[tokio::test]
async fn handshake_refused_when_server_does_not_pin_the_client_ca() {
    let a = node_ca();
    let b = node_ca();

    // A trusts B, but B is NOT trusted by A's client-cert verifier… invert: A trusts *nobody*,
    // so B's client certificate is rejected even though B pins A.
    let a_tls = NodeTls::new(a.clone(), TrustStore::new()).unwrap();
    let b_tls = NodeTls::new(
        b.clone(),
        TrustStore::from_fingerprints([a.ca_fingerprint().to_string()]),
    )
    .unwrap();

    let (addr, server) = run_server(a_tls).await;
    let result = try_client(addr, b_tls).await;
    assert!(result.is_err(), "client must be refused: {result:?}");
    assert!(
        server.await.unwrap().is_none(),
        "server must reject the handshake"
    );
}

#[tokio::test]
async fn handshake_refused_when_client_does_not_pin_the_server_ca() {
    let a = node_ca();
    let b = node_ca();

    // A trusts B's client cert, but B pins nobody, so B rejects A's server certificate.
    let a_tls = NodeTls::new(
        a.clone(),
        TrustStore::from_fingerprints([b.ca_fingerprint().to_string()]),
    )
    .unwrap();
    let b_tls = NodeTls::new(b.clone(), TrustStore::new()).unwrap();

    let (addr, server) = run_server(a_tls).await;
    let result = try_client(addr, b_tls).await;
    assert!(
        result.is_err(),
        "client must refuse the unpinned server: {result:?}"
    );
    let _ = server.await;
}

#[tokio::test]
async fn distrust_refuses_a_previously_trusted_peer() {
    let a = node_ca();
    let b = node_ca();

    let a_trust = TrustStore::from_fingerprints([b.ca_fingerprint().to_string()]);
    let a_tls = NodeTls::new(a.clone(), a_trust.clone()).unwrap();
    let b_tls = NodeTls::new(
        b.clone(),
        TrustStore::from_fingerprints([a.ca_fingerprint().to_string()]),
    )
    .unwrap();

    // Distrust B before any connection: replace A's trust set with the empty set.
    a_trust.replace(std::iter::empty());

    let (addr, server) = run_server(a_tls).await;
    let result = try_client(addr, b_tls).await;
    assert!(
        result.is_err(),
        "distrusted peer must be refused: {result:?}"
    );
    assert!(server.await.unwrap().is_none());
}
