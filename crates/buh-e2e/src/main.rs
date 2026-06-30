//! buh testnet end-to-end harness.
//!
//! Drives the *real* client messaging path against a live buh node over PQ-mTLS:
//! two in-process identities (a sender that initiates, a recipient that owns a
//! queue), a sealed first flight (PQXDH handshake + ratchet ciphertext) pushed to
//! the recipient's queue, then pulled back, opened, verified, and acked. There is
//! no inter-node forwarding in buh (peering is for mutual auth only), so a single
//! conversation runs against ONE node — this proves seal -> push -> pull -> open ->
//! ack on a real deployed `:31415` node.
//!
//! The `:31415` port is mutual-TLS with no anonymous path, so a client must present
//! a leaf whose CA the node trusts. Usage is two phases:
//!
//!   buh-e2e mint  --out <dir>                       # prints the client CA fingerprint
//!   # operator: buh-cli peer trust <that-fp>  on the node
//!   buh-e2e send  --client-ca <dir> --node <host:port> --node-ca-fp <fp> [--message <t>]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use rustls::pki_types::ServerName;

use buh_api::tls::{NodeTls, TrustStore};
use buh_core::NodePki;
use buh_crypto::identity::IdentityKeyPair;
use buh_crypto::pqxdh::{InitialMessage, initiate, respond};
use buh_crypto::prekey::PrekeyBundle;
use buh_crypto::ratchet::RatchetState;
use buh_data::RcgenNodeCa;
use buh_entities::dto::{EnvelopeAccepted, PullResponse, PushEnvelope};

#[derive(Parser)]
#[command(name = "buh-e2e", about = "buh testnet end-to-end message harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create (or load) the harness client CA in `--out` and print its fingerprint.
    Mint {
        #[arg(long)]
        out: PathBuf,
    },
    /// Run the full seal -> push -> pull -> open -> ack flow against a live node.
    Send {
        /// Directory holding the client CA minted earlier (its CA the node must trust).
        #[arg(long)]
        client_ca: PathBuf,
        /// Live node address, `host:port` (the node's BUH_NODE_PORT, e.g. testnet.buh.fm:31415).
        #[arg(long)]
        node: String,
        /// The node's CA fingerprint to pin (from `GET /v1/health` or the admin API).
        #[arg(long)]
        node_ca_fp: String,
        /// Plaintext to seal and round-trip.
        #[arg(long, default_value = "hello from buh-e2e — sealed, relayed, opened")]
        message: String,
    },
}

/// Load (creating if absent) a CA in `dir`; the persisted key makes the fingerprint stable.
fn load_ca(dir: PathBuf) -> Result<Arc<dyn NodePki>> {
    Ok(Arc::new(
        RcgenNodeCa::load_or_init(
            dir,
            vec!["buh-e2e-client".to_string()],
            Duration::from_secs(3600),
        )
        .context("init/load client CA")?,
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Mint { out } => {
            let ca = load_ca(out)?;
            println!("{}", ca.ca_fingerprint());
            Ok(())
        }
        Cmd::Send {
            client_ca,
            node,
            node_ca_fp,
            message,
        } => send(client_ca, &node, &node_ca_fp, &message).await,
    }
}

async fn send(client_ca: PathBuf, node: &str, node_ca_fp: &str, message: &str) -> Result<()> {
    let client = load_ca(client_ca)?;
    let client_tls = NodeTls::new(
        client.clone(),
        TrustStore::from_fingerprints([node_ca_fp.to_string()]),
    )
    .context("build client PQ-mTLS config")?;
    let conn = Conn::new(node, client_tls)?;

    println!("== buh end-to-end message ==");
    println!("node          {node}  (pin CA {node_ca_fp})");
    println!("client CA     {}", client.ca_fingerprint());

    // --- crypto: recipient publishes a prekey bundle; sender initiates against it. ---
    let recipient_id = IdentityKeyPair::generate();
    let (recipient_secrets, recipient_bundle) = PrekeyBundle::generate(&recipient_id, true);
    let bundle_blob = recipient_bundle.encode(); // hand the public bundle to the sender

    let sender_id = IdentityKeyPair::generate();
    let sender_view = PrekeyBundle::decode(&bundle_blob).context("decode bundle (sender view)")?;
    let (handshake, root) = initiate(&sender_id, &sender_view);
    let mut sender_session = RatchetState::initiator(root, sender_view.signed_prekey);
    let ciphertext = sender_session
        .encrypt(message.as_bytes())
        .context("ratchet encrypt")?;
    let initial = handshake.encode();

    // The recipient's queue id is an opaque 32-byte capability; possession == authorization.
    let queue: [u8; 32] = rand::random();
    let queue_hex = hex::encode(queue);
    println!("queue         {queue_hex}");
    println!("plaintext     {message:?}");

    // --- push the first flight (handshake, then ciphertext), oldest first. ---
    let id_initial = conn
        .push(&queue_hex, &initial, 300)
        .await
        .context("push handshake")?;
    let id_cipher = conn
        .push(&queue_hex, &ciphertext, 300)
        .await
        .context("push ciphertext")?;
    println!("pushed        handshake={id_initial}  ciphertext={id_cipher}");

    // --- pull them back from the live node (long-poll up to 5s). ---
    let pulled = conn.pull(&queue_hex, 5).await.context("pull")?;
    if pulled.envelopes.len() < 2 {
        bail!("expected 2 envelopes back, got {}", pulled.envelopes.len());
    }
    println!("pulled        {} envelopes", pulled.envelopes.len());

    // --- recipient opens the first flight: respond to the handshake, decrypt the message. ---
    let recipient_view = PrekeyBundle::decode(&bundle_blob).context("decode bundle (recipient)")?;
    let msg = InitialMessage::decode(&pulled.envelopes[0].payload).context("decode handshake")?;
    let root = respond(&recipient_view, &recipient_secrets, &msg).context("pqxdh respond")?;
    let mut recipient_session = RatchetState::responder(root, recipient_secrets.signed_prekey);
    let opened = recipient_session
        .decrypt(&pulled.envelopes[1].payload)
        .context("ratchet decrypt")?;

    if opened != message.as_bytes() {
        bail!(
            "decrypted plaintext mismatch: {:?}",
            String::from_utf8_lossy(&opened)
        );
    }
    println!("opened        {:?}", String::from_utf8_lossy(&opened));
    println!("verify        plaintext MATCHES ✓ (PQ-mTLS transport + PQXDH/ratchet)");

    // --- ack both, then re-pull to confirm delete-on-ack. ---
    for env in &pulled.envelopes {
        let eid = env.envelope_id.to_string();
        let acked = conn
            .ack(&queue_hex, &eid)
            .await
            .with_context(|| format!("ack {eid}"))?;
        if !acked {
            bail!("ack of {eid} returned acknowledged=false");
        }
    }
    let after = conn
        .pull(&queue_hex, 0)
        .await
        .context("re-pull after ack")?;
    if !after.envelopes.is_empty() {
        bail!("queue not empty after ack: {} left", after.envelopes.len());
    }
    println!("acked         both envelopes; queue empty on re-pull ✓");
    println!("== OK: end-to-end message sealed, relayed through the live node, and opened ==");
    Ok(())
}

/// A PQ-mTLS HTTP/1.1 client to one node. Opens a fresh TLS connection per request
/// (Connection: close) — simple and sufficient for a harness.
struct Conn {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    tls: NodeTls,
}

impl Conn {
    fn new(node: &str, tls: NodeTls) -> Result<Self> {
        let (host, port) = node.rsplit_once(':').context("node must be host:port")?;
        let server_name = ServerName::try_from(host.to_string()).context("invalid server name")?;
        Ok(Self {
            host: host.to_string(),
            port: port.parse().context("invalid port")?,
            server_name,
            tls,
        })
    }

    async fn push(&self, queue_hex: &str, payload: &[u8], ttl_seconds: i64) -> Result<String> {
        let body = serde_json::to_string(&PushEnvelope {
            payload: payload.to_vec(),
            ttl_seconds,
        })?;
        let (status, body) = self
            .request(
                "POST",
                &format!("/v1/queue/{queue_hex}/envelopes"),
                Some(&body),
            )
            .await?;
        if status != 200 && status != 201 {
            bail!("push -> HTTP {status}: {body}");
        }
        Ok(serde_json::from_str::<EnvelopeAccepted>(&body)?
            .envelope_id
            .to_string())
    }

    async fn pull(&self, queue_hex: &str, wait: u64) -> Result<PullResponse> {
        let path = format!("/v1/queue/{queue_hex}/envelopes?wait={wait}&limit=16");
        let (status, body) = self.request("GET", &path, None).await?;
        if status != 200 {
            bail!("pull -> HTTP {status}: {body}");
        }
        Ok(serde_json::from_str(&body)?)
    }

    async fn ack(&self, queue_hex: &str, envelope_id: &str) -> Result<bool> {
        let path = format!("/v1/queue/{queue_hex}/envelopes/{envelope_id}/ack");
        let (status, body) = self.request("POST", &path, None).await?;
        if status != 200 {
            bail!("ack -> HTTP {status}: {body}");
        }
        Ok(serde_json::from_str::<serde_json::Value>(&body)?
            .get("acknowledged")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false))
    }

    /// One request/response over a fresh PQ-mTLS connection; returns (status, body).
    async fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
        let connector = TlsConnector::from(Arc::new(self.tls.client_config()?));
        let tcp = TcpStream::connect((self.host.as_str(), self.port)).await?;
        let mut stream = connector.connect(self.server_name.clone(), tcp).await?;

        let body = body.unwrap_or("");
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.host,
            body.len(),
        );
        stream.write_all(req.as_bytes()).await?;

        let mut buf = Vec::new();
        match stream.read_to_end(&mut buf).await {
            Ok(_) => {}
            // Some servers drop the TCP connection without a TLS close_notify after a
            // Connection: close response; that's fine as long as we got the bytes.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => {}
            Err(e) => return Err(e.into()),
        }
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .context("no HTTP status line")?;
        let resp_body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b)
            .unwrap_or("")
            .to_string();
        Ok((status, resp_body))
    }
}
