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

    /// The [`CoreConfig`] derived from the relay knobs.
    #[must_use]
    pub fn core_config(&self) -> CoreConfig {
        CoreConfig {
            default_ttl_seconds: self.relay.default_ttl_seconds,
            max_ttl_seconds: self.relay.max_ttl_seconds,
            max_payload_bytes: self.relay.max_payload_bytes,
            max_pull_limit: self.relay.max_pull_limit,
        }
    }
}
