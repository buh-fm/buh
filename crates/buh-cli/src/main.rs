//! buh operator/admin CLI.
//!
//! Covers datastore migration, the TTL sweep, the per-node CA (`ca init|rotate|show`), and the
//! peer-CA trust registry (`peer trust|distrust|list`) — the operator surface of the
//! decentralised PQ-mTLS deviation (`doc/design.md` §5.1).

#![forbid(unsafe_code)]

use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

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
        Command::Peer(cmd) => run_peer(&cli.db_path, cmd).await?,
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

async fn run_peer(db_path: &str, cmd: PeerCommand) -> anyhow::Result<()> {
    let stack = stack(db_path).await?;
    stack.migrate().await?;
    let registry = TursoPeerTrust::new(stack.db.clone());

    match cmd {
        PeerCommand::Trust { ca_fp, note } => {
            registry.trust(&ca_fp, note.as_deref()).await?;
            println!("trusting peer CA {ca_fp}");
        }
        PeerCommand::Distrust { ca_fp } => {
            if registry.distrust(&ca_fp).await? {
                println!("distrusted peer CA {ca_fp}");
            } else {
                println!("peer CA {ca_fp} was not trusted");
            }
        }
        PeerCommand::List => {
            let peers = registry.list().await?;
            if peers.is_empty() {
                println!("no trusted peer CAs");
            }
            for p in peers {
                match p.note {
                    Some(note) => println!("{}  {}", p.ca_fingerprint, note),
                    None => println!("{}", p.ca_fingerprint),
                }
            }
        }
    }
    Ok(())
}

/// SANs are only meaningful for issued leaves, not CA management; stamp a sane default.
fn default_sans() -> Vec<String> {
    vec!["localhost".to_string()]
}
