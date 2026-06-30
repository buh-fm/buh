//! The buh node daemon: a blind relay/mailbox HTTP API.
//!
//! Milestone 1 binds loopback and speaks plain HTTP/JSON. Phase 6 replaces the listener with
//! self-served PQ-mTLS (X25519MLKEM768) under a decentralised per-node CA — see
//! `doc/design.md` §5.1 and the implementation plan's "Node trust model".

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::EnvFilter;

use buh_api::config::{AppConfig, BlobConfig, PkiConfig};
use buh_api::router::router;
use buh_api::state::AppState;
use buh_api::tls::{NodeTls, TrustStore};
use buh_data::DataStack;

/// Command-line arguments.
#[derive(Debug, Parser)]
#[command(
    name = "buh-api",
    version,
    about = "buh blind relay/mailbox node daemon"
)]
struct Cli {
    /// Path to the configuration TOML file.
    #[arg(long, env = "BUH_CONFIG")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::load(cli.config.as_deref())?;
    init_tracing(&config.log_format);

    let mut stack = DataStack::connect(&config.db_path, config.core_config()).await?;
    stack.migrate().await?;
    tracing::info!(db_path = %config.db_path, "datastore ready");

    if config.blob.enabled {
        stack = wire_blob(stack, &config.blob)?;
        tracing::info!(backend = %config.blob.backend, "blob role enabled");
    }

    // PQ-mTLS opt-in: a node serving the decentralised per-node CA needs its PKI + trust ports.
    if config.pki.enabled {
        stack = stack.with_node_pki(
            &config.pki.dir,
            config.pki.sans.clone(),
            Duration::from_secs(config.pki.leaf_ttl_hours * 3600),
        )?;
    }

    let state = AppState {
        ctx: stack.ctx.clone(),
        max_wait: Duration::from_secs(config.relay.max_wait_seconds),
    };
    let app = router(state);

    if config.pki.enabled {
        serve_pqmtls(app, &stack, &config.pki).await
    } else {
        serve_plain(app, &config.bind).await
    }
}

/// Plain-HTTP loopback ingress: the dev/web-demo mode (and what the integration tests exercise
/// through the router directly). No certificates.
async fn serve_plain(app: axum::Router, bind: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::warn!(bind = %bind, "buh-api listening (PLAIN HTTP — dev/loopback mode, PQ-mTLS off)");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// PQ-mTLS ingress: serve the router over X25519MLKEM768 mutual TLS, pinning peer CAs from the
/// trust registry, with the leaf auto-rotating on an in-process timer.
async fn serve_pqmtls(app: axum::Router, stack: &DataStack, pki: &PkiConfig) -> anyhow::Result<()> {
    let node_pki = stack
        .ctx
        .pki
        .clone()
        .expect("pki port set when pki.enabled");
    let registry = stack
        .ctx
        .peer_trust
        .clone()
        .expect("peer_trust port set when pki.enabled");

    // Load the trusted peer-CA set into the live snapshot the verifiers read.
    let trust = TrustStore::new();
    refresh_trust(&trust, registry.as_ref()).await;

    let node_tls = NodeTls::new(node_pki.clone(), trust.clone())?;
    tracing::info!(
        ca_fingerprint = %node_pki.ca_fingerprint(),
        node_bind = %pki.node_bind,
        "PQ-mTLS node: share this CA fingerprint with peers/clients to be trusted"
    );

    // In-process leaf rotation + periodic trust refresh.
    {
        let node_tls = node_tls.clone();
        let trust = trust.clone();
        let registry = registry.clone();
        let every = Duration::from_secs(pki.rotate_every_hours.max(1) * 3600);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.tick().await; // consume the immediate first tick
            loop {
                tick.tick().await;
                match node_tls.rotate_leaf() {
                    Ok(exp) => tracing::info!(not_after_ms = exp, "rotated PQ-mTLS leaf"),
                    Err(e) => tracing::error!(error = %e, "leaf rotation failed"),
                }
                refresh_trust(&trust, registry.as_ref()).await;
            }
        });
    }

    let acceptor = TlsAcceptor::from(Arc::new(node_tls.server_config()?));
    let listener = TcpListener::bind(&pki.node_bind).await?;
    tracing::info!(node_bind = %pki.node_bind, "buh-api listening (PQ-mTLS)");

    let shutdown = shutdown_signal();
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

/// Replace the live trust snapshot with the current registry contents.
async fn refresh_trust(trust: &TrustStore, registry: &dyn buh_core::PeerTrustRegistry) {
    match registry.list().await {
        Ok(peers) => trust.replace(peers.into_iter().map(|p| p.ca_fingerprint)),
        Err(e) => tracing::error!(error = %e, "failed to load peer trust registry"),
    }
}

/// Attach the configured blob backend to the data stack, enabling the node's blob role. The
/// `s3` backend requires the daemon to be built with the `s3` feature.
fn wire_blob(stack: DataStack, blob: &BlobConfig) -> anyhow::Result<DataStack> {
    match blob.backend.as_str() {
        "fs" => Ok(stack.with_fs_blob(&blob.fs_root)),
        "s3" => {
            #[cfg(feature = "s3")]
            {
                let settings = buh_data::S3Settings {
                    endpoint: blob.s3_endpoint.clone(),
                    region: blob.s3_region.clone(),
                    access_key: blob.s3_access_key.clone(),
                    secret_key: blob.s3_secret_key.clone(),
                };
                Ok(stack.with_s3_blob(&settings))
            }
            #[cfg(not(feature = "s3"))]
            {
                anyhow::bail!("blob backend \"s3\" requires building buh-api with the `s3` feature")
            }
        }
        other => anyhow::bail!("unknown blob backend {other:?} (expected \"fs\" or \"s3\")"),
    }
}

/// Initialize structured logging: JSON under journald (or when `log_format = "json"`),
/// pretty otherwise.
fn init_tracing(log_format: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,buh_api=debug"));
    let use_json = log_format == "json"
        || (log_format == "auto" && std::env::var_os("JOURNAL_STREAM").is_some());

    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if use_json {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// Resolve when SIGINT (Ctrl-C) or SIGTERM is received, so axum can drain in-flight requests.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => tracing::error!(error = %e, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("shutdown signal received, draining");
}
