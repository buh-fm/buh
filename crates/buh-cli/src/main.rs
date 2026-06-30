//! buh operator/admin CLI.
//!
//! Covers datastore migration, the per-node CA (`ca init|rotate|show`), peer-CA trust management
//! (`peer trust|distrust|list`), and a mutual-PQ-mTLS connectivity check (`peer ping`) — the
//! operator surface of the decentralised PQ-mTLS deviation (`doc/design.md` §5.1).
//!
//! `peer` commands talk to the running node's loopback admin API, because Turso locks the
//! datastore exclusively (a second process cannot open it while the daemon runs). They fall back
//! to opening the DB directly only when the daemon is unreachable.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use buh_api::peer::probe_peer;
use buh_api::tls::{NodeTls, TrustStore};
use buh_core::{CoreConfig, NodePki, PeerTrustRegistry, mailbox};
use buh_data::{DataStack, RcgenNodeCa, TursoPeerTrust};

/// Leaf validity is irrelevant to CA-management commands; any value loads the CA.
const NOMINAL_LEAF_TTL: Duration = Duration::from_secs(48 * 3600);

/// buh operator/admin CLI.
#[derive(Debug, Parser)]
#[command(name = "buh-cli", version, about = "buh operator/admin CLI")]
struct Cli {
    /// Path to the embedded Turso datastore.
    #[arg(long, env = "BUH_DB_PATH", default_value = "buh-relay.db")]
    db_path: String,
    /// Directory holding this node's CA (key + cert).
    #[arg(long, env = "BUH_PKI__DIR", default_value = "/var/lib/buh/pki")]
    pki_dir: String,
    /// Loopback admin API of the running node. `peer` commands use it so they work while the
    /// daemon holds the datastore; they fall back to the local DB only when it is unreachable.
    #[arg(long, env = "BUH_ADMIN_URL", default_value = "http://127.0.0.1:8081")]
    admin_url: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Apply pending datastore migrations.
    Migrate,
    /// Delete expired envelopes (TTL sweep). Prints the number removed.
    Sweep,
    /// Manage this node's CA (the identity peers pin).
    #[command(subcommand)]
    Ca(CaCommand),
    /// Manage the peer-CA trust registry (which peers this node accepts over PQ-mTLS).
    #[command(subcommand)]
    Peer(PeerCommand),
}

#[derive(Debug, Subcommand)]
enum CaCommand {
    /// Create the node CA if absent (idempotent), then print its fingerprint.
    Init,
    /// Print this node's CA fingerprint (the value peers/clients pin).
    Show,
    /// Re-key the CA — generate a brand-new CA, backing up the old one to `*.bak`. Destructive:
    /// every peer must re-pin the new fingerprint. Requires `--force`.
    Rotate {
        /// Confirm the destructive re-key.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Debug, Subcommand)]
enum PeerCommand {
    /// Trust a peer node by its CA fingerprint (lowercase hex SHA-256; `:` separators allowed).
    Trust {
        /// The peer CA fingerprint to pin.
        ca_fp: String,
        /// Optional note recording who/what this CA belongs to.
        #[arg(long)]
        note: Option<String>,
    },
    /// Stop trusting a peer CA. Refused on the peer's next handshake.
    Distrust {
        /// The peer CA fingerprint to remove.
        ca_fp: String,
    },
    /// List the trusted peer CAs.
    List,
    /// Verify mutual PQ-mTLS connectivity to a peer at `addr` (host:port). Succeeds only when both
    /// nodes trust each other's CA: this node pins the peer's CA (read from the running node via
    /// the admin API, or the local DB if the daemon is down) and the peer must trust this node's
    /// CA. Reports the peer's advertised CA fingerprint + health.
    Ping {
        /// Peer node address, `host:port` (the peer's BUH_NODE_PORT).
        addr: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,buh_cli=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();

    match cli.command {
        Command::Migrate => {
            stack(&cli.db_path).await?.migrate().await?;
            println!("migrations applied");
        }
        Command::Sweep => {
            let stack = stack(&cli.db_path).await?;
            stack.migrate().await?;
            let removed = mailbox::sweep(&stack.ctx).await?;
            println!("swept {removed} expired envelope(s)");
        }
        Command::Ca(cmd) => run_ca(&cli.pki_dir, cmd)?,
        Command::Peer(cmd) => run_peer(&cli.db_path, &cli.pki_dir, &cli.admin_url, cmd).await?,
    }

    Ok(())
}

/// Open the datastore (no roles attached — CLI commands wire what they need).
async fn stack(db_path: &str) -> anyhow::Result<DataStack> {
    Ok(DataStack::connect(db_path, CoreConfig::default()).await?)
}

fn run_ca(pki_dir: &str, cmd: CaCommand) -> anyhow::Result<()> {
    match cmd {
        CaCommand::Init => {
            let ca = RcgenNodeCa::load_or_init(pki_dir, default_sans(), NOMINAL_LEAF_TTL)?;
            println!("CA ready in {pki_dir}");
            println!("ca_fingerprint {}", ca.ca_fingerprint());
        }
        CaCommand::Show => {
            let ca = RcgenNodeCa::load_or_init(pki_dir, default_sans(), NOMINAL_LEAF_TTL)?;
            println!("{}", ca.ca_fingerprint());
        }
        CaCommand::Rotate { force } => {
            if !force {
                anyhow::bail!(
                    "ca rotate re-keys the CA and changes the fingerprint every peer pins; \
                     re-run with --force to confirm"
                );
            }
            let ca = RcgenNodeCa::rekey(pki_dir, default_sans(), NOMINAL_LEAF_TTL)?;
            println!("CA re-keyed; old material backed up to *.bak in {pki_dir}");
            println!("ca_fingerprint {}", ca.ca_fingerprint());
            println!("peers must now re-pin this fingerprint");
        }
    }
    Ok(())
}

async fn run_peer(
    db_path: &str,
    pki_dir: &str,
    admin_url: &str,
    cmd: PeerCommand,
) -> anyhow::Result<()> {
    let admin = admin_hostport(admin_url);

    match cmd {
        PeerCommand::Trust { ca_fp, note } => {
            let body = serde_json::json!({ "ca_fingerprint": ca_fp, "note": note }).to_string();
            match admin_req(&admin, "POST", "/admin/peers", Some(&body)).await {
                Some((status, _)) => {
                    ensure_ok(status)?;
                    println!("trusting peer CA {ca_fp} (applied to the running node)");
                }
                None => {
                    open_registry(db_path)
                        .await?
                        .trust(&ca_fp, note.as_deref())
                        .await?;
                    println!("trusting peer CA {ca_fp} (direct DB — daemon not running)");
                }
            }
        }
        PeerCommand::Distrust { ca_fp } => {
            match admin_req(&admin, "DELETE", &format!("/admin/peers/{ca_fp}"), None).await {
                Some((status, body)) => {
                    ensure_ok(status)?;
                    let removed = json_bool(&body, "removed");
                    println!(
                        "{} (applied to the running node)",
                        if removed {
                            format!("distrusted peer CA {ca_fp}")
                        } else {
                            format!("peer CA {ca_fp} was not trusted")
                        }
                    );
                }
                None => {
                    let removed = open_registry(db_path).await?.distrust(&ca_fp).await?;
                    let how = "direct DB — daemon not running";
                    if removed {
                        println!("distrusted peer CA {ca_fp} ({how})");
                    } else {
                        println!("peer CA {ca_fp} was not trusted ({how})");
                    }
                }
            }
        }
        PeerCommand::List => {
            let peers = trusted_fingerprints_with_notes(&admin, db_path).await?;
            if peers.is_empty() {
                println!("no trusted peer CAs");
            }
            for (fp, note) in peers {
                match note {
                    Some(note) => println!("{fp}  {note}"),
                    None => println!("{fp}"),
                }
            }
        }
        PeerCommand::Ping { addr } => {
            // Present this node's leaf and pin every CA the running node currently trusts.
            let ca = RcgenNodeCa::load_or_init(pki_dir, default_sans(), NOMINAL_LEAF_TTL)?;
            let trusted = trusted_fingerprints_with_notes(&admin, db_path).await?;
            let trust = TrustStore::from_fingerprints(trusted.into_iter().map(|(fp, _)| fp));
            let node_tls = NodeTls::new(Arc::new(ca), trust)?;

            match probe_peer(&node_tls, &addr).await {
                Ok(health) => {
                    println!("reachable: {}", health.status_line);
                    match health.ca_fingerprint {
                        Some(fp) => println!("peer CA {fp} — mutual PQ-mTLS OK (both nodes trust)"),
                        None => println!("peer did not advertise a CA fingerprint"),
                    }
                }
                Err(e) => {
                    println!("unreachable or refused: {e:#}");
                    println!(
                        "(mutual trust required: you must `peer trust <peer-ca-fp>` and the peer \
                         must trust your CA — share `ca show`)"
                    );
                }
            }
        }
    }
    Ok(())
}

/// Read the trusted peer CAs (with notes) from the running node's admin API, falling back to the
/// local datastore when the daemon is not running.
async fn trusted_fingerprints_with_notes(
    admin: &str,
    db_path: &str,
) -> anyhow::Result<Vec<(String, Option<String>)>> {
    if let Some((status, body)) = admin_req(admin, "GET", "/admin/peers", None).await {
        ensure_ok(status)?;
        let v: serde_json::Value = serde_json::from_str(&body)?;
        let peers = v["peers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| {
                        let fp = p["ca_fingerprint"].as_str()?.to_string();
                        let note = p["note"].as_str().map(str::to_string);
                        Some((fp, note))
                    })
                    .collect()
            })
            .unwrap_or_default();
        return Ok(peers);
    }
    // Daemon down: read the DB directly.
    let peers = open_registry(db_path).await?.list().await?;
    Ok(peers
        .into_iter()
        .map(|p| (p.ca_fingerprint, p.note))
        .collect())
}

/// Open the peer-trust registry directly (the daemon-down fallback path).
async fn open_registry(db_path: &str) -> anyhow::Result<TursoPeerTrust> {
    let stack = stack(db_path).await?;
    stack.migrate().await?;
    Ok(TursoPeerTrust::new(stack.db.clone()))
}

/// Turn a non-2xx admin response into an error.
fn ensure_ok(status: u16) -> anyhow::Result<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        anyhow::bail!("admin API returned HTTP {status}")
    }
}

/// Extract `http://host:port` (or `host:port`) down to the `host:port` the admin client dials.
fn admin_hostport(url: &str) -> String {
    let s = url.strip_prefix("http://").unwrap_or(url);
    s.split('/').next().unwrap_or(s).to_string()
}

/// Best-effort boolean field lookup in a small JSON body.
fn json_bool(body: &str, key: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v[key].as_bool())
        .unwrap_or(false)
}

/// Send a minimal HTTP/1.1 request to the loopback admin API. Returns `Some((status, body))` on a
/// completed exchange, or `None` when the daemon is unreachable (so the caller falls back to the
/// local datastore). The admin API is plain HTTP on loopback — no TLS.
async fn admin_req(
    hostport: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Option<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(hostport).await.ok()?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {hostport}\r\nConnection: close\r\n");
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }

    stream.write_all(req.as_bytes()).await.ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.ok()?;
    let resp = String::from_utf8_lossy(&buf);

    let status = resp
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Some((status, body))
}

/// SANs are only meaningful for issued leaves, not CA management; stamp a sane default.
fn default_sans() -> Vec<String> {
    vec!["localhost".to_string()]
}
