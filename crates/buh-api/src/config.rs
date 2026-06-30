//! Daemon configuration: figment layering (defaults → file → env).

use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};

use buh_core::CoreConfig;

/// Top-level daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Address to bind the HTTP listener (loopback in Milestone 1; PQ-mTLS ingress in Phase 6).
    pub bind: String,
    /// Filesystem path to the embedded Turso datastore.
    pub db_path: String,
    /// `auto` (JSON under journald, pretty otherwise), `json`, or `pretty`.
    pub log_format: String,
    /// Relay tuning knobs.
    pub relay: RelayConfig,
    /// Blob-role configuration (disabled by default — a node opts into the blob role).
    pub blob: BlobConfig,
    /// PQ-mTLS ingress + per-node CA (disabled by default; `bind` stays plain loopback for dev).
    pub pki: PkiConfig,
    /// Loopback operator admin API (peer-trust management against a running node).
    pub admin: AdminConfig,
}

/// Loopback admin API configuration (`doc/design.md` §5.1).
///
/// Because Turso locks the datastore exclusively, `buh-cli` cannot manage trust by opening the DB
/// while the daemon runs; instead the daemon exposes a small admin API here, on **loopback only**.
/// It is started only when [`PkiConfig::enabled`] is also set (trust management needs the registry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    /// Whether to start the loopback admin listener (alongside a PQ-mTLS node).
    pub enabled: bool,
    /// Address for the admin listener. **Keep this on loopback** — there is no auth.
    pub bind: String,
}

/// PQ-mTLS / per-node-CA configuration (`doc/design.md` §5.1, the decentralised-CA deviation).
///
/// When `enabled`, the node generates (on first start) and self-serves its own CA, binds a
/// PQ-mTLS listener on `node_bind` (the standardised `BUH_NODE_PORT`, forwarded from the edge),
/// and auto-rotates its leaf in process. When disabled, the node serves plain HTTP on `bind` —
/// the loopback mode the dev web demo and tests use, with no certificates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    /// Whether this node serves PQ-mTLS (and thus is its own CA). Off → plain loopback on `bind`.
    pub enabled: bool,
    /// Directory holding the persisted CA key + cert (`/var/lib/buh/pki` in prod).
    pub dir: String,
    /// Address for the PQ-mTLS ingress listener (the standardised `BUH_NODE_PORT`).
    pub node_bind: String,
    /// Subject alternative names stamped on issued leaves (hostnames/IPs the node answers to).
    pub sans: Vec<String>,
    /// Validity window of each issued leaf, in hours.
    pub leaf_ttl_hours: u64,
    /// How often the in-process timer issues a fresh leaf, in hours (well inside `leaf_ttl_hours`).
    pub rotate_every_hours: u64,
}

/// Blob-role configuration. A node runs the blob role only when `enabled` is set; it then
/// stores opaque, client-encrypted ciphertext (`doc/design.md` §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobConfig {
    /// Whether this node runs the blob role at all.
    pub enabled: bool,
    /// Backend: `"fs"` (filesystem/ZFS) or `"s3"` (S3/MinIO — requires the `s3` build feature).
    pub backend: String,
    /// Root directory for the `fs` backend.
    pub fs_root: String,
    /// Maximum accepted blob size, in bytes.
    pub max_blob_bytes: usize,
    /// `s3` endpoint URL (e.g. `http://localhost:9000`).
    pub s3_endpoint: String,
    /// `s3` region label.
    pub s3_region: String,
    /// `s3` access key id.
    pub s3_access_key: String,
    /// `s3` secret access key.
    pub s3_secret_key: String,
}

/// Relay tuning knobs, mirrored into [`CoreConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Default TTL applied when none (or an out-of-range value) is requested, in seconds.
    pub default_ttl_seconds: i64,
    /// Maximum TTL a client may request, in seconds.
    pub max_ttl_seconds: i64,
    /// Maximum accepted envelope payload size, in bytes.
    pub max_payload_bytes: usize,
    /// Maximum number of envelopes returned by a single pull.
    pub max_pull_limit: i64,
    /// Maximum long-poll wait a client may request, in seconds.
    pub max_wait_seconds: u64,
    /// How often the daemon sweeps expired envelopes, in seconds. The sweep runs **in process**
    /// because Turso locks the datastore exclusively — a separate `buh-cli sweep` cannot run while
    /// the daemon holds the DB.
    pub sweep_interval_seconds: u64,
}

impl Default for AppConfig {
    fn default() -> Self {
        let core = CoreConfig::default();
        Self {
            bind: "127.0.0.1:8080".to_string(),
            db_path: "buh-relay.db".to_string(),
            log_format: "auto".to_string(),
            relay: RelayConfig {
                default_ttl_seconds: core.default_ttl_seconds,
                max_ttl_seconds: core.max_ttl_seconds,
                max_payload_bytes: core.max_payload_bytes,
                max_pull_limit: core.max_pull_limit,
                max_wait_seconds: 30,
                sweep_interval_seconds: 3600,
            },
            blob: BlobConfig {
                enabled: false,
                backend: "fs".to_string(),
                fs_root: "buh-blobs".to_string(),
                max_blob_bytes: core.max_blob_bytes,
                s3_endpoint: String::new(),
                s3_region: "us-east-1".to_string(),
                s3_access_key: String::new(),
                s3_secret_key: String::new(),
            },
            pki: PkiConfig {
                enabled: false,
                dir: "/var/lib/buh/pki".to_string(),
                node_bind: "0.0.0.0:8443".to_string(),
                sans: vec!["localhost".to_string()],
                leaf_ttl_hours: 48,
                rotate_every_hours: 24,
            },
            admin: AdminConfig {
                enabled: true,
                bind: "127.0.0.1:8081".to_string(),
            },
        }
    }
}

impl AppConfig {
    /// Load configuration: built-in defaults, then an optional TOML file, then `BUH_`-prefixed
    /// environment variables (e.g. `BUH_BIND`, `BUH_DB_PATH`).
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut fig = Figment::from(Serialized::defaults(AppConfig::default()));
        if let Some(p) = path {
            fig = fig.merge(Toml::file(p));
        }
        let cfg: AppConfig = fig.merge(Env::prefixed("BUH_").split("__")).extract()?;
        Ok(cfg)
    }

    /// The [`CoreConfig`] derived from the relay/blob knobs.
    #[must_use]
    pub fn core_config(&self) -> CoreConfig {
        CoreConfig {
            default_ttl_seconds: self.relay.default_ttl_seconds,
            max_ttl_seconds: self.relay.max_ttl_seconds,
            max_payload_bytes: self.relay.max_payload_bytes,
            max_pull_limit: self.relay.max_pull_limit,
            max_blob_bytes: self.blob.max_blob_bytes,
        }
    }
}
