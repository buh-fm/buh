# buh

> *An anti-hub.* A messaging platform where independent, untrusted node runners provide
> asynchronous (store-and-forward) messaging infrastructure — text, recorded audio, and
> recorded video — secured end-to-end with quantum-safe cryptography, and incentivised
> without the platform ever becoming a money instrument.

The defining constraint is that **the node runner is untrusted**. A node is a blind
store-and-forward relay plus a blob store; all cryptographic intelligence (identity, key
agreement, ratcheting) lives in the client. See [`doc/design.md`](doc/design.md) for the full
architecture and [the implementation plan](#status) for the current build.

## Status

Pre-implementation, building Milestone 1. What works today:

- **Blind relay/mailbox node** (`buh-api`): push a sealed envelope to an opaque queue,
  long-poll/pull it, acknowledge delivery. The relay stores only `queue_id → envelope_refs`,
  TTL, and delivery receipts — no identities, no social graph (`doc/design.md` §3.1).

Not yet built (see the plan): the client crypto core (PQXDH + Double Ratchet), the invite
flow, blob media, decentralised PQ-mTLS ingress, and the settlement seam.

## Architecture & conventions

buh follows the org-wide conventions in [`~/git/architecture/generic.md`](https://git.lair.cafe/)
(Rust cargo workspace, hardened systemd units, firewalld, SELinux enforcing, Fedora targets).
Three **deliberate, documented deviations** are forced by the untrusted-node threat model:

1. **Datastore: embedded [Turso](https://github.com/tursodatabase/turso) (pure-Rust SQLite
   rewrite), not central Postgres.** A node runs on a stranger's machine and must be
   zero-maintenance with no external database service or account. The `MailboxRepo` trait
   keeps the engine swappable (SQLite/libSQL is a file-format-compatible fallback). Because we
   use the native `turso` crate rather than `sqlx`, there is no compile-time query checking —
   all SQL is centralised in `buh-data` and guarded by the integration suite.
2. **TLS: self-served PQ-mTLS (X25519MLKEM768) under a decentralised per-node CA**, not the
   internal step-ca PKI. Each node holds its own CA, auto-rotates its own leaf certs, and
   keeps a peer trust registry; clients/peers pin a node's CA (carried in the invite's queue
   descriptor). *(Phase 6 — not yet implemented.)*
3. **License: AGPL-3.0-only**, not GPL-3.0-or-later — keeps the future PQ-rekey path (Signal's
   AGPL SPQR ratchet) open and fits a privacy project.

## Workspace

| Crate | Role |
|---|---|
| `buh-entities` | Domain types, DTOs, errors. No I/O. |
| `buh-crypto` | Client crypto core (PQ identity, PQXDH, Double Ratchet, wire codec). Compiles to WASM. The node never links it. |
| `buh-core` | Business logic + port traits (`MailboxRepo`, `BlobStore`, `SettlementBackend`). |
| `buh-data` | Adapters implementing the ports over the Turso datastore. |
| `buh-api` | The node daemon: blind relay/mailbox HTTP API. |
| `buh-cli` | Operator CLI (migrate, sweep). |

## Build & test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Run a relay locally

```sh
# Apply migrations and start the node (binds 127.0.0.1:8080 by default).
cargo run -p buh-cli -- --db-path buh-relay.db migrate
cargo run -p buh-api          # reads BUH_* env / --config <toml>

# Exercise it: push a (base64) sealed payload to an opaque 32-byte queue, then pull it.
q=$(printf '11%.0s' {1..32})
curl -s localhost:8080/v1/queue/$q/envelopes \
  -H 'content-type: application/json' \
  -d '{"payload":"aGVsbG8=","ttl_seconds":3600}'
curl -s localhost:8080/v1/queue/$q/envelopes
```

## License

AGPL-3.0-only. See [`license`](license).
