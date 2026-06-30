# buh — Implementation Plan (Milestone 1)

## Context

`buh` is a greenfield, end-to-end-encrypted, store-and-forward messaging platform whose
defining constraint is that **the node runner is untrusted**. The full architecture is in
`doc/design.md`; the org-wide build conventions are in `~/git/architecture/generic.md`
(plus the TLS/deploy companions). Today the repo contains only `doc/design.md` — there is
no code, no `Cargo.toml`, and it is not yet a git repository.

This plan turns the design's suggested roadmap (`design.md` §13) and the architecture
conventions into a concrete first implementation milestone. The goal of Milestone 1 is the
smallest **honest end-to-end slice**: two clients exchange a sealed 1:1 text message through
a blind relay node, using the real post-quantum crypto path — proving the architecture
before any of the genuinely-deferred pieces (blob media, settlement, redundancy, directory)
are built.

A near-identical sibling project, **AudioBlume** (`~/git/audioblume/audioblume`), already
implements the exact `entities/core/data/api/cli` workspace decomposition, the
provider-swappable `BlobStore` trait `design.md` §3.2 explicitly references ("identical in
shape to the AudioBlume TTS trait pattern"), sqlx-0.8 with compile-time checks, and the full
`asset/` deployment layout. **We scaffold `buh` by copying and renaming AudioBlume's
structure**, not from scratch.

---

## Decisions (confirmed)

1. **Scope of this pass: through Phase 4** (scaffold → relay round-trip → `buh-crypto` core →
   invite + E2E text demo = `design.md` §13 items 1–3). Phases 5–7 (blob media, decentralised
   PQ-mTLS hardening, stub settlement seam) are fast-follows, authorised separately. Each phase
   is an independent, committable unit.
2. **License: AGPL-3.0-only.** Keeps the future PQ-rekey path open (Signal's **SPQR** ratchet,
   `design.md` §5.3, is AGPL-3.0 with a network clause that reaches a served web client) and is
   the right posture for a privacy project. Set in the workspace manifest.
3. **Node TLS: self-served rustls + PQ-mTLS with a decentralised, per-node CA** — NOT the
   org-internal step-ca PKI. Each node holds its own CA, auto-rotates its own short-lived leaf
   certs, and maintains a peer trust registry of (mis)trusted peer CAs. Clients/peers pin the
   node's CA (carried in the invite's queue descriptor), not the leaf. One standardised
   collision-free TCP port (`BUH_NODE_PORT`) that operators forward from their OPNsense edge.
   This is a deliberate, documented deviation from `generic.md` §11. See the **Node trust model**
   section. (Built in Phase 6; Phases 1–4 run on loopback.)
4. **Source hosting: Gitea.** `git init` locally, remote
   `gitea@git.internal:buh/buh.git` (https://git.lair.cafe/buh/buh). Created/pushed in Phase 0.
5. **Per-node datastore: embedded [Turso Database](https://github.com/tursodatabase/turso)
   (pure-Rust SQLite rewrite, ex-"Limbo").** buh nodes run on untrusted third-party
   infrastructure, so `generic.md` §5's central-cluster Postgres model does not apply, and its
   "Turso" entry (the *hosted, synced, token-auth* product) is also a non-starter — a stranger's
   node can't depend on an external account/service. The store must be embedded and
   zero-maintenance. We use **Turso Database embedded** via the native `turso` Rust crate:
   pure-Rust (cleanest static-musl build, fewest deps, aligns with the Rust-everywhere ethos),
   SQLite-compatible SQL + file format, async-native, with **encryption-at-rest** and MVCC
   concurrent writers as bonuses for an unattended on-disk store. Long-poll is served by an
   **in-process** `Notify` map keyed by queue (a node is one process). **Engineering
   consequences:** the `turso` crate is not `sqlx`, so we forgo `sqlx` compile-time query
   checking + the `.sqlx` cache (deviation from `generic.md` §5) — mitigated by centralising all
   SQL in the `MailboxRepo` adapter and covering it with the integration suite; and we run a
   **small migration runner** (or idempotent startup DDL) rather than `sqlx::migrate!`. Because
   Turso is SQLite-file-format-compatible, SQLite/libSQL remains a trivial drop-in fallback
   behind the same `MailboxRepo` trait if Turso ever bites. (`redb` considered — pure-Rust but
   KV, worse fit; RocksDB rejected — C++ build + LSM throughput we don't need.)

Minor defaults (decided, not blocking): ML-DSA signing mode = **hedged/randomized** (FIPS 204
default); `buh-crypto` exposes its WASM FFI behind a **`wasm` cargo feature** (single crate,
keeps the core `#![forbid(unsafe_code)]`); blob adapter uses **`aws-sdk-s3`** to match the
AudioBlume house pattern (not `object_store`); node CA + leaf cert generation via **`rcgen`**
(pure Rust X.509).

---

## Architecture decisions (settled by research)

- **Crypto core is Rust → WASM**, not pure TypeScript. The decisive factor: the deferred
  PQ-rekey milestone (`design.md` §5.3, "ML-KEM layered, PQ3 level-3 shape, no wire break")
  is Signal's **SPQR**, which exists **only in Rust** and is formally verified. A TS core
  would have to adopt WASM anyway. Rust/WASM also gives one audited implementation + one wire
  codec shared by the node-adjacent types, the web client, and any future Tauri client —
  exactly the shared `buh-crypto` `design.md` §12 envisions.
- **The node never depends on `buh-crypto`.** A relay/blob node treats envelopes as opaque
  bytes (`design.md` §3.1). `buh-crypto` is client-side; it lives in the workspace because
  `web/` is built from its `wasm-pack` output, but no node binary links it.
- **`buh-core` is honestly thin.** A blind relay has almost no business logic. We keep the
  ports/adapters layering (`generic.md` §1) for testability and role-separability, but do not
  manufacture fake logic to fill `core`.

---

## Node trust model (decentralised CA — deviation from `generic.md` §11)

buh nodes are run by independent, mutually-untrusted operators on the public internet, so the
org-internal step-ca PKI does **not** apply to the node protocol surface. Instead:

- **Each node holds its own CA** (generated on first run via `rcgen`, or an operator-supplied
  existing CA) and issues + **auto-rotates its own short-lived leaf certs** under it. Leaf
  rotation is routine and invisible to peers because peers pin the **CA**, not the leaf.
- **Peers and clients pin a node's CA fingerprint.** The queue descriptor inside an invite
  (`TAG_QUEUE_URI`) carries the hosting node's CA fingerprint, so a client trusts exactly the
  nodes its queues live on (TOFU at first contact, pinned thereafter). CA rotation is the rare,
  explicitly-signalled event — handled like a mailbox migration (`design.md` §10).
- **Each node maintains a peer trust registry**: peer node id → trusted/distrusted CA(s) +
  state. This is the substrate the stigmergic health/reputation gradient (`design.md` §10) will
  read and write; a fresh sybil node starts with no standing in anyone's registry.
- **One standardised, collision-free TCP port** (`BUH_NODE_PORT`, a named constant — exact
  value TBD, pick one unlikely to collide) that operators port-forward from their OPNsense edge.
  Client↔node and node↔node both use it with PQ-mTLS (X25519MLKEM768).
- rustls uses **custom cert verifiers backed by the registry** rather than a single trusted
  root — the core deviation, recorded in `readme.md`.

---

## Verified library / version choices (mid-2026)

| Concern | Crate | Version |
|---|---|---|
| Web framework / API | `axum` | 0.8 |
| Per-node store | Turso Database (`turso` crate, embedded, pure-Rust) | latest |
| Per-node store (drop-in fallback behind same trait) | SQLite/libSQL (file-format compatible) | — |
| TLS / PQ-mTLS (Phase 6) | `rustls` + `rustls-post-quantum` (X25519MLKEM768, aws-lc-rs) | rustls 0.23.27+ |
| Node CA + leaf cert generation (Phase 6) | `rcgen` (pure-Rust X.509) | latest |
| Blob backend (Phase 5) | `aws-sdk-s3` (MinIO/S3) + a filesystem adapter | — |
| ML-DSA-65 (FIPS 204) identity/signing | `ml-dsa` | 0.1.1 |
| ML-KEM-768 (FIPS 203) handshake KEM | `ml-kem` | 0.3.2 |
| X25519 | `x25519-dalek` | latest |
| XChaCha20-Poly1305 (media, Phase 5) | `chacha20poly1305` | latest |
| HKDF / SHA-2 (ratchet chains) | `hkdf` + `sha2` | latest |
| WASM bindings | `wasm-bindgen` + `wasm-pack`; `getrandom` (`js`) | — |
| Vite WASM integration | `vite-plugin-wasm` | 3.6.0 |
| Future PQ-rekey (NOT vendored now; wire bytes reserved only) | Signal `SPQR` | AGPL-3.0 |

PQ primitives in both ecosystems are NIST-vector-tested but not independently audited; this
is a known, accepted state (gated behind KATs — see Testing).

---

## Workspace layout (target)

```
buh/                              cargo workspace + Vite app (per generic.md §1, §4)
├─ Cargo.toml                     [workspace.package] single version 0.1.0, edition 2024,
│                                 resolver 3, AGPL-3.0-only; one [workspace.dependencies]
├─ rust-toolchain.toml            pin stable to match CI
├─ readme.md                      what/build/run/deploy; notes the decentralised-CA deviation
├─ crates/
│  ├─ buh-entities/               wire DTOs + error enums; no I/O; ts-rs/specta-exportable
│  ├─ buh-crypto/                 CLIENT crypto core (crate-type cdylib+rlib; `wasm` feature)
│  │  └─ src/{identity,prekey,kem,pqxdh,aead,invite,state}.rs
│  │     + ratchet/{mod,chain,header}.rs + wire/{mod,v1,codec}.rs
│  ├─ buh-core/                   ports (MailboxRepo, BlobStore, SettlementBackend,
│  │                              NodePki/PeerTrustRegistry) + thin logic
│  ├─ buh-data/                   adapters: TursoMailboxRepo, (later) S3/Fs BlobStore,
│  │  │                           StubSettlement, RcgenNodeCa, peer trust registry store
│  │  └─ migrations/0001_init.sql (applied by a small runner; turso ≠ sqlx::migrate!)
│  ├─ buh-api/                    thin Axum daemon; role-gated (relay|blob) at runtime
│  └─ buh-cli/                    operator CLI: migrate, sweep, queue stats, ca init/rotate, peer trust
├─ web/                           Vite + React + SWC + TS; consumes buh-crypto wasm-pack pkg
│  └─ src/lib/crypto/             generated pkg + typed TS facade + KeyStore/IndexedDB
└─ asset/                         manifest.yml, systemd/, firewalld/, config/, sql/
```

---

## Phase-by-phase plan

### Phase 0 — Workspace scaffold
Copy AudioBlume's root `Cargo.toml`, `rust-toolchain.toml`, and crate manifest shapes;
rename `audioblume-*` → `buh-*`. Create the five crates + `buh-crypto`. Set license to
**AGPL-3.0-only**. Add `web/` Vite-React-SWC-TS app and wire `wasm-pack` +
`vite-plugin-wasm`; prove a trivial `Uint8Array` round-trips Rust↔TS in the browser before
any real crypto. `git init`, set remote `gitea@git.internal:buh/buh.git`, create the repo on
Gitea (https://git.lair.cafe/buh/buh) and push the scaffold.
- Model files: `~/git/audioblume/audioblume/Cargo.toml`, `.../rust-toolchain.toml`,
  `.../crates/*/Cargo.toml`.

### Phase 1 — Relay node round-trip (`design.md` §13 item 1)  ← first real milestone
The smallest blind relay that accepts and serves one sealed envelope.
- **`buh-entities`**: `QueueId` (newtype, opaque 32-byte capability), `EnvelopeId`,
  `NewEnvelope`, `StoredEnvelope`, `PushEnvelope`/`PullResponse`/`AckRequest` DTOs,
  `DeliveryReceipt`, `EntityError`. (Settlement value types `Credit`/`Payout`/etc. stubbed
  here too so the trait compiles in Phase 7.)
- **`buh-data/migrations/0001_init.sql`** (Turso/SQLite SQL): `envelopes (id INTEGER PK,
  queue_id BLOB CHECK length 32, envelope_id BLOB/uuid, payload BLOB, received_at INTEGER
  epoch-ms, expires_at INTEGER, delivered_at INTEGER NULL)` + `delivery_receipts (id, queue_id,
  envelope_id, pulled_at)`; partial index on `(queue_id, received_at) WHERE delivered_at IS
  NULL`; index on `expires_at`. **No users/queues/ownership tables — by design** (`design.md`
  §3.1: relay stores only `queue_id → envelope_refs`, TTL, receipts; cannot enumerate a social
  graph). Applied by a **small migration runner** in `buh-data` (ordered `.sql` files + a
  `schema_version` table), invoked by `buh-cli migrate` — not `sqlx::migrate!`.
- **`buh-core/src/ports.rs`**: `MailboxRepo` trait — `push`, `pull(limit)`, `ack`,
  `expire(now)`, `wait_for_envelope(timeout)`. Plus `BlobStore` and `SettlementBackend`
  traits declared now (impls land in Phases 5/7). Model: `.../audioblume-core/src/ports.rs`.
- **`buh-data`**: `TursoMailboxRepo` over an embedded Turso `Database`/`Connection` (`turso`
  crate, async), data file under `/var/lib/buh/` (encryption-at-rest enabled). **All SQL lives
  here** (centralised to offset the loss of `sqlx` compile-time checks). `wait_for_envelope` is
  served by an **in-process** `Notify` map keyed by queue (a node is a single process). No DB
  password, no central cluster, no external account: the store is local to the operator's node.
- **`buh-api`**: Axum router under `/v1/`, bound to **loopback** for now:
  `POST /v1/queue/{queue_id}/envelopes` (push; queue_id is the only capability — sealed
  sender, no sender auth), `GET /v1/queue/{queue_id}/envelopes?limit=N` (synchronous pull
  first), `POST /v1/queue/{queue_id}/envelopes/{envelope_id}/ack`, `GET /v1/health`.
- **Done test** (`crates/buh-api/tests/`, temp-file Turso DB per run, `generic.md` §12):
  migrate → push opaque payload to `queue_id=[0x11;32]` → pull it back → ack → assert second
  pull is empty and a `delivery_receipts` row exists. The node stays blind throughout. This
  suite is also the primary guard against the dropped `sqlx` compile-time checks.

### Phase 2 — Crypto foundation: wire codec + identity + AEAD (`design.md` §13 item 2, part 1)
- **`buh-crypto/src/wire/`** FIRST (everything serializes through it): 2-byte prelude
  `[MAGIC=0xB0][WIRE_VERSION=0x01]`, then a capability-flags varint, then length-prefixed
  **TLV** fields (never bare positional structs). Reserve PQ-rekey tags now without emitting
  them (`TAG_SPQR_CHUNK=0x20`, `TAG_PQ_EPOCH=0x21`, `TAG_PQ_KEM_CT=0x22`). Version + flags go
  in the AEAD AAD so downgrade is authenticated. **This is the literal `design.md` §5.3
  "add PQ rekey later without a wire-format break" contract.** Add golden-byte tests +
  `cargo-fuzz` target.
- **`identity.rs`** (`ml-dsa` 0.1.1, hedged mode): `IdentityKeyPair` keygen/sign/verify — the
  user *is* their key (`design.md` §4).
- **`aead.rs`** (`chacha20poly1305`): XChaCha20-Poly1305 sealing primitive (used for envelope
  sealing now; media sealing in Phase 5).
- Each primitive gated on its KAT/NIST-vector suite passing **both native and `wasm-pack
  test --headless`** (catches `getrandom`/wasm divergence).

### Phase 3 — Handshake + ratchet (`design.md` §13 item 2, part 2)
- **`kem.rs`**: X25519 (`x25519-dalek`) + ML-KEM-768 (`ml-kem` 0.3.2) hybrid wrappers.
- **`prekey.rs`**: prekey bundle `{identity_pub, signed_x25519_prekey, signed_mlkem768_encaps,
  one_time_prekeys[], capability_flags, signature}`, signed by the ML-DSA identity key;
  verify-on-parse always.
- **`pqxdh.rs`**: PQXDH hybrid handshake — root key from
  `HKDF(DH(eph, peer_x25519_prekey) ‖ mlkem_shared_secret ‖ …)`, responder's ML-DSA bundle
  bound into the transcript (harvest-now-decrypt-later defence, `design.md` §5.2).
- **`ratchet/`**: standard Double Ratchet — HKDF-SHA256 symmetric chains (already PQ-safe,
  `design.md` §5.3), X25519 DH ratchet step, bounded skipped-message-key storage; header
  carried inside the versioned wire frame with reserved PQ fields.
- Property/interop tests (`proptest`): two in-memory sessions exchange thousands of messages
  with out-of-order/dropped/skipped delivery; native↔wasm cross-decode of the same frames.

### Phase 4 — Invite flow + E2E text demo (`design.md` §13 item 3)  ← milestone payoff
- **`invite.rs`**: SimpleX-shape one-time signed invite, encoded in the same versioned wire
  codec, wrapped `buh1:<base64url>` for QR/paste. TLV fields: `TAG_QUEUE_URI` (N redundant
  relay queue descriptors, **each carrying the hosting node's CA fingerprint for pinning** —
  see Node trust model), `TAG_IDENTITY_PUB`, `TAG_PREKEY_BUNDLE`, `TAG_INVITE_NONCE`
  (one-time / spam-proof), `TAG_EXPIRY`, `TAG_SIGNATURE` (ML-DSA over the whole body).
  `parseInvite` verifies signature before returning anything.
- **WASM facade + TS `KeyStore`**: tiny envelope-oriented API (`generateIdentity`,
  `publishablePrekeyBundle`, `createInvite`/`parseInvite`, `initiateSession`/`acceptSession`,
  `encryptMessage`/`decryptMessage`); every mutating call **returns new state**, persisted
  transactionally to **IndexedDB** (sealed under an Argon2id-derived key). `KeyStore`
  interface with `IndexedDbKeyStore` now, `TauriKeyStore` later (same trait-swap discipline
  as blob/settlement).
- **Done demo**: Alice `createInvite` → Bob `parseInvite` → `initiateSession`/`acceptSession`
  → ratcheted text round-trips **through the real Phase-1 relay** (push to Bob's queue, Bob
  pulls + decrypts). This is `design.md`'s end-to-end 1:1 text goal.

### Phase 5 — Blob role + content-key media path (`design.md` §13 item 4) — fast-follow
`BlobStore` adapters (`S3BlobStore` copied from `~/git/audioblume/audioblume/crates/audioblume-data/src/s3.rs`,
plus `FsBlobStore` for ZFS/local); `PUT/GET /v1/blob/{bucket}/{key}` serving opaque
ciphertext; `buh-crypto` `sealMedia`/`openMedia` (fresh XChaCha20-Poly1305 content key per
file); only `{contentKey, locator}` folded into the ratchet envelope. Blob node holds bytes
it cannot read.

### Phase 6 — Decentralised PQ-mTLS ingress + node trust model — fast-follow
See the **Node trust model** section below for the design. Implementation:
- **`buh-core` `NodePki` + `PeerTrustRegistry` ports**; **`buh-data`** `RcgenNodeCa`
  (CA gen + leaf issuance + auto-rotation via `rcgen`) and a registry store (in the embedded
  store). CA private key + leaf live under `/var/lib/buh/pki/`.
- **`buh-api/src/tls.rs`**: `rustls` + `rustls-post-quantum` X25519MLKEM768 `CryptoProvider`,
  with **custom `ServerCertVerifier`/`ClientCertVerifier` backed by the peer trust registry**
  (not a single trusted root). Leaf auto-rotates on an in-process timer; no `step.service`.
- **`buh-cli`**: `ca init` / `ca rotate` / `peer trust|distrust <ca-fingerprint>`.
- Bind on the standardised `BUH_NODE_PORT` (operators forward it from their OPNsense edge);
  switch relay/blob off loopback. Long-poll already in-process (Phase 1).

### Phase 7 — Stub settlement seam + deployment assets (`design.md` §13 item 8) — fast-follow
`StubSettlement` implementing the 4-method `SettlementBackend` trait (returns canned
quote/attestation, errors on `payout`); assert **no chain identifier leaks above the trait**
(`design.md` §8.5). Full `asset/`: `manifest.yml` (relay + blob components), hardened systemd
units + sysusers (`generic.md` §8; **no step-ca cert `.path` units** — the node rotates its own
leaf internally), firewalld XML opening `BUH_NODE_PORT` (default zone only), templated config,
`deploy.sh` (or the Gitea-Actions model). No central-DB bootstrap (embedded store). Model:
`~/git/audioblume/audioblume/asset/`.

**Explicitly NOT in this plan** (remain genuinely deferred per the design): mailbox
redundancy + in-band migration (§10), stigmergic reputation (§10), directory/DHT (§6.2),
UnifiedPush (§11), groups/MLS + multi-device/Sesame (§11), and the **OPEN edge-settlement /
fair-exchange design pass** (§9) — that is its own architecture pass, not code.

---

## Verification

- **Per crate**: `cargo fmt`, `cargo clippy --all-targets --all-features -- -D warnings`,
  `cargo test` (and `wasm-pack test --headless` for `buh-crypto`).
- **Crypto gate (non-negotiable)**: ML-KEM-768 / ML-DSA-65 / X25519 / XChaCha20-Poly1305 KATs
  pass native AND wasm; golden-byte wire-format corpus still decodes (the §5.3 no-break
  contract); forward-compat test (reserved PQ tag skipped in messaging, rejected in
  handshake); fuzz targets on the TLV codec + `parseInvite` + `decryptMessage` never panic;
  tampered-signature / AEAD-mismatch / replayed-prekey / truncated-frame all rejected.
- **Phase 1 done test**: the envelope round-trip integration test above (dedicated test DB).
- **Phase 4 done demo**: full invite → session → ratcheted text round-trip through the relay,
  driven from the `web/` app against a locally-running `buh-api`.
- **End-to-end**: run `buh-api` locally, open `web/` in two browser profiles, exchange a
  message, confirm the relay store shows only `(queue_id, envelope, received/delivered)` — no
  identity, no sender, no graph.
