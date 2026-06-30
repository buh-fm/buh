//! Serving the node router over plain HTTP (dev/loopback) or PQ-mTLS (`doc/design.md` §5.1).
//!
//! Both entry points take an already-bound [`TcpListener`] and a generic `shutdown` future, so
//! the daemon (`main.rs`) and the integration tests drive the exact same serving code — the tests
//! bind an ephemeral port and signal shutdown over a channel, the daemon binds the configured port
//! and shuts down on SIGINT/SIGTERM.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use buh_core::{Ctx, PeerTrustRegistry, mailbox};

use crate::tls::{NodeTls, TrustStore};

/// Spawn the in-process TTL sweep that deletes expired envelopes every `interval`.
///
/// The sweep runs inside the daemon — not as an external `buh-cli sweep` — because Turso locks the
/// datastore exclusively, so a second process cannot open the DB while the daemon holds it.
pub fn spawn_sweeper(ctx: Ctx, interval: Duration) {
    let interval = interval.max(Duration::from_secs(1));
    tracing::info!(interval_secs = interval.as_secs(), "TTL sweeper started");
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.tick().await; // consume the immediate first tick
        loop {
            tick.tick().await;
            match mailbox::sweep(&ctx).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(removed = n, "swept expired envelopes"),
                Err(e) => tracing::error!(error = %e, "TTL sweep failed"),
            }
        }
    });
}

/// Plain-HTTP ingress: the dev/web-demo loopback mode. No certificates.
pub async fn serve_plain(
    app: axum::Router,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    if let Ok(addr) = listener.local_addr() {
        tracing::warn!(bind = %addr, "buh-api listening (PLAIN HTTP — dev/loopback mode, PQ-mTLS off)");
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// Loopback operator admin API. Plain HTTP, bound to loopback only (no auth, no TLS) — it manages
/// peer trust on a running node, which Turso's exclusive lock otherwise makes impossible.
pub async fn serve_admin(
    app: axum::Router,
    listener: TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(admin_bind = %addr, "buh-api admin API listening (loopback)");
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

/// PQ-mTLS ingress: serve the router over X25519MLKEM768 mutual TLS, pinning peer CAs from the
/// trust registry, with the leaf auto-rotating on an in-process timer.
///
/// The initial trusted-CA set is loaded from `registry` into the live snapshot the verifiers read;
/// every `rotate_every` the node issues a fresh leaf and re-reads the registry, so trust changes
/// (`buh-cli peer trust|distrust`) take effect without a restart.
pub async fn serve_pqmtls(
    app: axum::Router,
    listener: TcpListener,
    node_tls: NodeTls,
    registry: Arc<dyn PeerTrustRegistry>,
    rotate_every: Duration,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    // Load the trusted peer-CA set into the live snapshot the verifiers read.
    refresh_trust(node_tls.trust(), registry.as_ref()).await;

    // In-process leaf rotation + periodic trust refresh.
    spawn_rotation_timer(node_tls.clone(), registry.clone(), rotate_every);

    let acceptor = TlsAcceptor::from(Arc::new(node_tls.server_config()?));
    if let Ok(addr) = listener.local_addr() {
        tracing::info!(node_bind = %addr, "buh-api listening (PQ-mTLS)");
    }

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => {
                tracing::info!("shutdown signal received, no longer accepting connections");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => { tracing::warn!(error = %e, "accept failed"); continue; }
                };
                let acceptor = acceptor.clone();
                let svc = TowerToHyperService::new(app.clone());
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls) => {
                            let io = TokioIo::new(tls);
                            if let Err(e) =
                                ConnBuilder::new(TokioExecutor::new()).serve_connection(io, svc).await
                            {
                                tracing::debug!(error = %e, "connection closed with error");
                            }
                        }
                        // A refused handshake (unpinned/distrusted peer) is normal, not an error.
                        Err(e) => tracing::debug!(error = %e, peer = %peer, "TLS handshake refused"),
                    }
                });
            }
        }
    }
    Ok(())
}

/// Spawn the background timer that re-issues the TLS leaf and refreshes the trust snapshot.
fn spawn_rotation_timer(
    node_tls: NodeTls,
    registry: Arc<dyn PeerTrustRegistry>,
    rotate_every: Duration,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(rotate_every.max(Duration::from_secs(1)));
        tick.tick().await; // consume the immediate first tick
        loop {
            tick.tick().await;
            match node_tls.rotate_leaf() {
                Ok(exp) => tracing::info!(not_after_ms = exp, "rotated PQ-mTLS leaf"),
                Err(e) => tracing::error!(error = %e, "leaf rotation failed"),
            }
            refresh_trust(node_tls.trust(), registry.as_ref()).await;
        }
    });
}

/// Replace the live trust snapshot with the current registry contents.
pub async fn refresh_trust(trust: &TrustStore, registry: &dyn PeerTrustRegistry) {
    match registry.list().await {
        Ok(peers) => trust.replace(peers.into_iter().map(|p| p.ca_fingerprint)),
        Err(e) => tracing::error!(error = %e, "failed to load peer trust registry"),
    }
}
