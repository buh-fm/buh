//! The buh node daemon: a blind relay/mailbox HTTP API.
//!
//! Milestone 1 binds loopback and speaks plain HTTP/JSON. Phase 6 replaces the listener with
//! self-served PQ-mTLS (X25519MLKEM768) under a decentralised per-node CA — see
//! `doc/design.md` §5.1 and the implementation plan's "Node trust model".

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use buh_api::config::{AppConfig, BlobConfig};
use buh_api::router::router;
use buh_api::serve::{serve_plain, serve_pqmtls, spawn_sweeper};
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

    // In-process TTL sweep (an external `buh-cli sweep` cannot run while the daemon holds the DB).
    spawn_sweeper(
        stack.ctx.clone(),
        Duration::from_secs(config.relay.sweep_interval_seconds),
    );

    let state = AppState {
        ctx: stack.ctx.clone(),
        max_wait: Duration::from_secs(config.relay.max_wait_seconds),
    };
    let app = router(state);

    if config.pki.enabled {
        let node_pki = stack.ctx.pki.clone().expect("pki set when pki.enabled");
        let registry = stack
            .ctx
            .peer_trust
            .clone()
            .expect("peer_trust set when pki.enabled");
        let node_tls = NodeTls::new(node_pki.clone(), TrustStore::new())?;
        tracing::info!(
            ca_fingerprint = %node_pki.ca_fingerprint(),
            node_bind = %config.pki.node_bind,
            "PQ-mTLS node: share this CA fingerprint with peers/clients to be trusted"
        );
        let listener = TcpListener::bind(&config.pki.node_bind).await?;
        let rotate_every = Duration::from_secs(config.pki.rotate_every_hours * 3600);
        serve_pqmtls(
            app,
            listener,
            node_tls,
            registry,
            rotate_every,
            shutdown_signal(),
        )
        .await
    } else {
        let listener = TcpListener::bind(&config.bind).await?;
        serve_plain(app, listener, shutdown_signal()).await
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
