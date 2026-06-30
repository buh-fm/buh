//! Client-side PQ-mTLS: probe a peer node over the same X25519MLKEM768 mutual TLS the ingress
//! serves (`doc/design.md` §5.1 — "PQ TLS on every hop: client↔node and node↔node").
//!
//! This is the first consumer of [`NodeTls::client_config`]. It exists so an operator can confirm
//! a trust relationship actually works end to end: a probe succeeds **only when both nodes trust
//! each other's CA** — this node must pin the peer's CA (to accept its server cert) and the peer
//! must pin this node's CA (to accept the client cert it presents). It deliberately does **not**
//! forward envelopes; generic node↔node forwarding belongs to the deferred mailbox-redundancy work
//! (§10), and adding it now would be surface with no consumer.

use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use rustls::pki_types::ServerName;

use crate::tls::NodeTls;

/// The outcome of a successful peer probe.
#[derive(Debug)]
pub struct PeerHealth {
    /// The peer's HTTP status line (e.g. `HTTP/1.1 200 OK`).
    pub status_line: String,
    /// The CA fingerprint the peer advertises on `/v1/health`, if any.
    pub ca_fingerprint: Option<String>,
}

/// Open a PQ-mTLS connection to `addr` using `node_tls`'s client config (which presents this
/// node's leaf and pins the peer's CA), fetch `/v1/health`, and parse the result.
///
/// Errors if the peer is unreachable or the **mutual** handshake is refused — i.e. this node does
/// not pin the peer's CA, or the peer does not trust this node's CA.
pub async fn probe_peer(node_tls: &NodeTls, addr: &str) -> anyhow::Result<PeerHealth> {
    let host = addr
        .rsplit_once(':')
        .map_or(addr, |(h, _)| h)
        .trim_matches(|c| c == '[' || c == ']') // strip IPv6 brackets
        .to_string();

    let connector = TlsConnector::from(Arc::new(node_tls.client_config()?));
    let tcp = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connect to {addr}"))?;
    let name = ServerName::try_from(host).context("invalid peer host for TLS")?;
    let mut tls = connector
        .connect(name, tcp)
        .await
        .context("PQ-mTLS handshake refused (each node must trust the other's CA)")?;

    tls.write_all(
        format!("GET /v1/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .context("send health request")?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf)
        .await
        .context("read health response")?;

    let response = String::from_utf8_lossy(&buf);
    let status_line = response
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    let ca_fingerprint = response
        .split_once("\r\n\r\n")
        .and_then(|(_, body)| serde_json::from_str::<serde_json::Value>(body.trim()).ok())
        .and_then(|v| {
            v.get("ca_fingerprint")
                .and_then(|f| f.as_str())
                .map(str::to_string)
        });

    Ok(PeerHealth {
        status_line,
        ca_fingerprint,
    })
}
