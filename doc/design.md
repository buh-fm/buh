# buh — Architecture & Design Document

> *An anti-hub.* A messaging platform where independent, untrusted node runners provide
> asynchronous (store-and-forward) messaging infrastructure — text, recorded audio, and
> recorded video — secured end-to-end with quantum-safe cryptography, and incentivised
> without the platform ever becoming a money instrument.

**Status:** architecture draft, pre-implementation
**Audience:** implementers and reviewers
**Scope:** this document is detailed enough to plan implementation. It deliberately leaves
one component (edge settlement / fair exchange) marked as open, because the austere design
makes it the genuinely hard piece and it deserves its own design pass.

---

## 1. Design philosophy

buh inverts the homeserver model. The defining constraint is that **the node runner is
untrusted**. Everything else follows from refusing to leak anything meaningful to a person
who hosts a node out of self-interest or malice.

Three principles drive every decision below:

1. **Keep nodes dumb.** A node is a blind store-and-forward relay plus a blob store. All
   intelligence — identity, key agreement, ratcheting, routing decisions — lives in the
   client. A node that knows almost nothing can betray almost nothing.
2. **Asynchronicity is the enabler.** Because messaging is *not* real-time, a dumb encrypted
   mailbox is sufficient. There is no session establishment, NAT traversal, or P2P path
   building between two online peers. Either party can be offline indefinitely.
3. **The values and the constraints select the same build.** The privacy thesis (leak
   nothing) and the regulatory constraint (don't be a money instrument) independently point
   at the same austere, non-custodial, hold-nothing design. Where they converge, we build;
   where a feature would compromise both at once (custody), we refuse it.

### Non-goals (v1)

- Real-time calling / live streaming. buh is recorded-message only by design.
- Group messaging at launch (see §11 — MLS is the target, but v1 is 1:1).
- A bespoke cryptocurrency or token. Explicitly never.
- The platform holding, denominating in, or redeeming value for fiat (see §8).

---

## 2. System overview

```
   ┌─────────────┐                                          ┌─────────────┐
   │   Alice     │                                          │    Bob      │
   │  (client)   │                                          │  (client)   │
   │             │                                          │             │
   │ identity KP │                                          │ identity KP │
   │ ratchet st. │                                          │ ratchet st. │
   └──────┬──────┘                                          └──────┬──────┘
          │ 1. push sealed envelope to Bob's queue                 │
          │    (sealed-sender, PQ-hybrid TLS)                      │
          ▼                                                        │
   ┌─────────────────────────┐    blob ciphertext     ┌──────────────────┐
   │  Relay / Mailbox node    │◄──────────────────────│  Blob store node  │
   │  (blind queue relay)     │   (locator + key       │  (opaque blobs)   │
   │  Postgres: queue_id →     │    travel in envelope) │  ZFS / MinIO / S3 │
   │  envelope_refs, TTL       │                        │  behind a trait   │
   └─────────────┬───────────┘                        └──────────────────┘
                 │ 2. Bob long-polls / is woken, pulls envelopes
                 ▼
          (Bob decrypts client-side, lazily fetches + decrypts blobs)

   ┌──────────────────────────────────────────────────────────────────────┐
   │  Optional / opt-in roles                                               │
   │   • Directory or DHT  — first-contact discovery (metadata-accumulating)│
   │   • Settlement backend — edge on-ramp / payout, swappable (ETH | SOL)  │
   └──────────────────────────────────────────────────────────────────────┘
```

The relay sees exactly one thing: *an opaque queue received an envelope, and later someone
pulled it.* That is the entire metadata surface.

---

## 3. Node roles

A node runner MAY run any subset of these roles. They are kept separable on purpose; merging
them re-accumulates metadata.

### 3.1 Relay / Mailbox

Holds small encrypted envelopes keyed by **queue ID**, with TTLs, and serves them on
authenticated pull. Per-node Postgres stores only:

- `queue_id → envelope_refs`
- envelope expiry / TTL
- delivery receipts (pull acknowledgements)

It never stores identities, never learns that two queues belong to the same user, and cannot
enumerate a social graph. Queues are **unidirectional**, one per contact-direction (the
SimpleX insight): the relay cannot correlate the two halves of a conversation.

### 3.2 Blob store

Handles recorded audio/video and any large payload. Media is **never** pushed through the
ratchet. Instead:

- The client encrypts each media file once under a fresh random content key
  (XChaCha20-Poly1305).
- The opaque ciphertext blob is stored on any blob node (or MinIO / S3 / ZFS behind a
  **provider-swappable trait**, identical in shape to the AudioBlume TTS trait pattern).
- Only the small **content key + blob locator** travel through the encrypted message channel.

This decouples the blob entirely from who is talking to whom and yields CDN-like fan-out for
free. A blob node holds bytes it cannot read.

### 3.3 Directory (optional, opt-in)

Maps human-readable identifiers → key bundles for discovery. This is the **one role that
accumulates metadata** and is therefore opt-in per operator. The protocol MUST work fully
without it (see §6).

### 3.4 Settlement backend (edge, optional)

Not a messaging role. Bridges service entitlement to value at the edges (§7–8). Swappable;
neither ETH nor SOL is committed in the core.

---

## 4. Identity

- Identity is a **user-held post-quantum keypair**, never node-bound. A user is their key,
  not an account on a server.
- **ML-DSA** (FIPS 204) for identity signing and for signing prekey bundles.
- Prekey bundles (for the handshake, §5) are signed by the ML-DSA identity key and published
  either out-of-band (invite) or to a directory/DHT.
- Loss/rotation and multi-device are explicitly harder in a decentralised model; see §11.

---

## 5. Cryptography

Three **independent** quantum-safety concerns. Treating them as one switch is the classic
mistake; they are separated here.

### 5.1 Transport (defence-in-depth only)

Hybrid PQ TLS on every hop: client↔node and node↔node. **X25519MLKEM768**. This is *not*
what protects content — it is layered defence. Aligns with the project-wide quantum-safe-TLS
standard.

### 5.2 Handshake / session setup (priority — harvest-now-decrypt-later)

This is where recorded traffic today becomes readable by a future quantum adversary, so it is
the priority.

- **PQXDH-style hybrid** initial key agreement: **X25519 + ML-KEM-768** (FIPS 203).
- Prekey bundles signed by the **ML-DSA** identity key.
- Result: an adversary who records today's handshake cannot decrypt it once they have a
  quantum computer.

### 5.3 Ongoing ratchet (the subtle part)

- A standard **Double Ratchet's symmetric KDF chains are already quantum-safe** (hash-based,
  256-bit). No change needed there.
- The quantum-vulnerable piece is the **asymmetric DH ratchet step** that provides
  post-compromise ("healing") security. PQXDH does **not** fix this — it only PQ-secures the
  initial handshake.
- **Decision:** ship **PQXDH-grade first**, and design the ratchet so **periodic PQ rekeying**
  (ML-KEM rekeys layered onto the ratchet, the Apple PQ3 "level 3" shape) can be added later
  **without a wire-format break.** This is an explicit wire-versioning requirement, not a
  vague aspiration.

### 5.4 Media at rest

Already opaque ciphertext under its per-file content key (§3.2). Nothing additional required
at the node.

### 5.5 SSH/TLS posture

Operational access to nodes uses quantum-safe SSH and TLS, consistent with the project
standard.

---

## 6. Discovery & first contact

The hardest privacy-vs-UX tradeoff in the system. Two mechanisms; the first is mandatory, the
second is strictly optional.

### 6.1 Out-of-band invites (primary, build first)

A user hands a contact a **one-time, signed invite** containing a queue + prekey bundle
(SimpleX shape). Properties:

- Zero discoverability, zero central honeypot.
- **Structurally spam-proof**: you can only message someone who gave you a queue.
- Cost: no "search for @rob and DM him."

### 6.2 Directory / DHT (optional, opt-in, later)

Human-readable lookup (username → key bundle). A metadata magnet and a centralisation point;
any directory node can be crawled to enumerate users; a DHT is also crawlable. Therefore:

- The protocol MUST function end-to-end **without** it.
- Prefer a **DHT mapping** over directory nodes if/when built, accepting crawlability.
- Build the invite path first; treat findability as a later, opt-in layer.

---

## 7. Message lifecycle

```
Alice composes
  └─ encrypts envelope through her ratchet session with Bob
       └─ if media present:
            ├─ encrypt blob under fresh content key (XChaCha20-Poly1305)
            ├─ upload ciphertext to a blob node
            └─ fold {locator + content key} into the envelope
  └─ push envelope to Bob's CURRENT mailbox queue on whatever node hosts it
       └─ sealed-sender semantics: relay never learns it was Alice

Bob
  └─ long-polls (or is woken via push, §11) on his queues
  └─ pulls envelopes
  └─ decrypts client-side
  └─ lazily fetches + decrypts any blobs

Relay observes only:  "opaque queue X received an envelope; later someone pulled it."
```

---

## 8. Economic model — incentivising node runners

### 8.1 The reasoning chain (settled)

1. Node runners are incentivised either (a) because they want to use the app, or (b) because
   they get paid. (a) limits utility below viability — most secure-messaging consumers will
   never run a node. So **(b): node runners get paid.**
2. A **new token is never created.** A token turns a messaging project into a token project
   (securities exposure, speculation, governance capture, incentive to optimise for price not
   delivery). Avoiding it is non-negotiable.
3. **The platform must not denominate in fiat (e.g. USDC).** A platform-level redeemable
   USD-denominated token is, in substance, an **e-money token** (MiCA EMT), makes the platform
   a **money transmitter / custodian**, and — because the tokens are anonymous bearer
   instruments — collides head-on with the EU AMLR anonymous-instrument prohibition. The
   privacy feature becomes the regulatory aggravator. A per-node earnings cap does **not**
   rescue this: EMT status and the anonymous-bearer prohibition are **qualitative** triggers
   with no de-minimis, and they attach to the **platform aggregate**, not the per-runner slice.

### 8.2 The escape — denominate in *service*, not money

The credit is a claim on **service from the network** — *"N byte-hours of mailbox / N MB of
egress"* — **not** a claim on a pot of fiat. A closed-loop prepaid **service voucher** has
real exemption precedent (EU EMD2 limited-network carve-out; US closed-loop prepaid
exemptions). The consumer prepays for a service; the platform never cashes credits back out to
money.

> **Closed-loop is what earns the exemption, and closed-loop is in tension with "node runners
> need spendable money."** That tension is the core money-architecture problem, and it is a
> money problem, not a crypto-primitive one.

### 8.3 The chosen instrument — non-custodial Privacy-Pass entitlement

Two candidate spend-layer shapes were considered:

| | Custodial service-mint (Cashu/Fedimint shape) | **Non-custodial Privacy-Pass entitlement (chosen)** |
|---|---|---|
| What the token is | Blind-signed bearer claim, mint holds backing | **Pure bearer entitlement: "proof of N units of relay service"** |
| Custody | Holds backing value | **Holds nothing** |
| Monetary semantics | Yes (redeemable) | **None** |
| Regulatory surface | EMT/AMLR crosshairs regardless of size | **Smallest possible — nothing to characterise** |
| UX | Better ("buy a roll, spend across nodes") | Harder (no pool to net against) |
| Settlement | Easier | **Harder — the open problem (§9)** |

**Decision: non-custodial Privacy-Pass entitlement.** The token is a blind bearer proof that
*some* paid-up consumer is entitled to *N units of relay service* — it only **anonymises which
paid-up consumer is consuming**. No pot of value is held anywhere. The consumer obtains
entitlement by paying at the **edge**, on whatever rail they choose; money moves
peer-to-peer between consumer and node, never through a platform pool.

> **Terminology note:** "ecash" here always means the *blind-bearer-token pattern* (a
> coat-check ticket — an unlinkable, redeemable claim on value held elsewhere), **never** a
> currency and never DigiCash-the-product. buh goes further than even the pattern's custodial
> form: Privacy Pass tokens carry **no monetary semantics at all**.

### 8.4 Why this is the *aggressive* posture, not the timid one

The non-custodial design does not flinch from a legal test — it **chooses the terrain**.
Regulators never put "encrypted relay of private correspondence" on trial; they put
"unlicensed anonymous fiat-claim bearer token" on trial. Holding nothing and denominating
nothing **denies them the money fight entirely**, leaving only the communication fight — the
one backed by Article 8 ECHR and Articles 7–8 of the Charter, with a sympathetic defendant.
A custodial mint, by contrast, makes some named human's liberty the test case under the law
written for exactly that instrument. **Protocols don't stand trial; people do.** Build
non-custodial and there is no one to charge on the money side.

### 8.5 Settlement backend — design for both chains, build one

The chain is the one component with no architectural opinion worth defending — pure
value-in/value-out plumbing. It appears in **exactly two methods and nowhere above them.**

```rust
trait SettlementBackend {
    async fn onramp_quote(&self, value: Credit) -> DepositInstructions;
    async fn confirm_deposit(&self, proof: DepositProof) -> Result<Credit>;
    async fn payout(&self, redeemed: Credit, dest: Payout) -> Result<TxRef>;
    async fn reserve_attestation(&self) -> SolvencyProof;
}
```

- Above the redemption boundary, **every component speaks abstract service credits and has
  never heard of a chain.** If a chain identifier leaks above this seam, "both" is broken.
- `EthSettlement` / `SolSettlement` implement the trait. Neither is committed in core.
- **Discipline:** design the seam for both, **build exactly one first.** The whole messaging +
  entitlement stack must run against a **stub/testnet** backend and prove the architecture
  before any mainnet wire-up. The test that the seam is right: the *second* backend is a
  weekend, not a rewrite. (Same discipline as provider-swappable-TTS-but-Kokoro-first.)

**Asymmetries the seam must tolerate (backends are not mirror images):**

- **Finality.** Solana fast-probabilistic vs. an L2's finality/withdrawal semantics. Each
  backend owns its own "confirmed enough" notion; the core treats settlement as **asynchronous
  and eventual** and never blocks on synchronous chain finality.
- **Account model & gasless UX.** ETH accounts vs. Solana rent/ATA/PDA differ at
  deposit-address generation; chain-abstraction maturity differs (ERC-4337 paymasters vs.
  Solana fee payers). Abstractable, not free.

**Two consumer segments converge here:** privacy-maximalists (crypto on-ramp, KYC-averse) and
normies (fiat, chain invisible) use different on-ramps but spend **identical anonymous
entitlement tokens** at nodes.

---

## 9. OPEN PROBLEM — edge settlement & fair exchange

This is the bill the austere design hands us, and it is deliberately unsolved here. Every easy
answer (a pool, a mint, a platform-controlled escrow) is exactly what §8 correctly refused to
build.

The problem statement:

- **Fair exchange against an untrusted node.** Did the node actually deliver the envelope, or
  take payment/entitlement and drop it? Clients should **release entitlement against a delivery
  signal** (recipient pull receipt) rather than prepaying into the dark — accepting some loss
  to bad actors, which reputation (§10) then penalises.
- **Matching edge payment to rendered service**, with **no central pot to net it out.**
- **Metering without metadata.** Pricing is **per-unit-of-service** (byte-hours, egress) in
  tokens — **never** per-conversation or per-recipient, or the billing system leaks the graph.

This is the next real architecture pass. It does not block building the messaging + crypto +
node stack against a stub settlement backend.

---

## 10. Node selection, health & anti-abuse

- **Mailbox redundancy.** Each user holds **N redundant mailboxes on independent nodes**, so a
  single node death is non-fatal. (Accepts that redundancy creates some cross-node correlation
  a global observer could exploit — a known, bounded tradeoff.)
- **Mailbox migration under churn (the crux).** Node runners come and go. Migration is done
  **in-band**: once a channel exists, Bob sends Alice a **signed "I've moved to node X"**
  message over the existing encrypted channel; she updates locally. The directory/DHT is then
  needed only for **first contact** and for **cold recovery** when *all* of a user's known
  mailboxes die at once.
- **Malicious nodes** can only **drop, delay, or attempt traffic analysis** — never read.
  Redundancy handles dropping; sealed-sender + blind queues blunt analysis.
- **Stigmergic health/reputation.** Uptime and delivery success are modelled as a **deposited
  gradient clients follow**, not a centrally-maintained scoreboard — a natural fit for the
  cichlid stigmergic model. A fresh **sybil swarm has no gradient** and therefore no pull on
  sensitive traffic. Payment does not stop sybils (it may subsidise them); reputation is the
  control.
- **Node discovery** uses **gossip or a DHT**, not static config (discovery-over-config).

---

## 11. Known-hard / deferred areas

- **Groups.** **MLS (RFC 9420)** is the right standard; PQ-MLS work exists. Heavy over blind
  relays. **v1 is 1:1 only**; groups are a deliberate later phase.
- **Multi-device.** **Sesame** is the reference; decentralisation makes it harder. Deferred.
- **Push notifications** without surrendering to FCM/APNs: **UnifiedPush** is the decentralised
  answer. Needed for "Bob is woken" without a central push monopoly.
- **Cold recovery** when all known mailboxes die simultaneously (depends on §6.2).

---

## 12. Technology stack

Aligned with established project conventions.

| Layer | Choice |
|---|---|
| Node backend (relay, blob, settlement adapters) | **Rust** |
| Per-node datastore | **Postgres** (queue_id → envelope_refs, TTL, receipts only), passwordless **mTLS** auth |
| Blob storage backend | provider-swappable **trait**: ZFS / MinIO / S3 |
| Client frontend | **Vite (React-SWC-TS)** |
| Workstations / servers | **latest Fedora** |
| Site routers | **OPNsense** |
| Site-to-site | **WireGuard** |
| SSH / TLS | **quantum-safe** throughout |
| Transport (app hops) | hybrid PQ TLS (**X25519MLKEM768**) |
| Settlement (edge, swappable) | `SettlementBackend` trait; ETH and SOL impls, neither in core |

**Cryptographic primitives summary:**

| Purpose | Primitive |
|---|---|
| Identity / prekey signing | **ML-DSA** (FIPS 204) |
| Handshake KEM (hybrid) | **X25519 + ML-KEM-768** (FIPS 203) |
| Transport KEM (hybrid) | **X25519MLKEM768** |
| Ratchet symmetric chains | hash-based KDF (already PQ-safe) |
| Ratchet PQ rekey (later, no wire break) | **ML-KEM** layered (PQ3 "level 3" shape) |
| Media-at-rest | **XChaCha20-Poly1305**, per-file content key |

---

## 13. Implementation roadmap (suggested ordering)

The ordering follows the "build the novel/hard part first, demote reversible decisions off the
critical path" discipline.

1. **Node skeleton (Rust):** relay/mailbox role + Postgres schema (queue_id → envelope_refs,
   TTL, receipts), mTLS, hybrid PQ TLS transport.
2. **Client core (Vite/React-SWC-TS):** identity keypair (ML-DSA), PQXDH-grade handshake
   (X25519 + ML-KEM-768), Double Ratchet with **wire versioning reserved for PQ rekey.**
3. **Out-of-band invite flow** (§6.1) — first contact, end-to-end 1:1 text.
4. **Blob role + content-key media path** (§3.2) — recorded audio/video; provider-swappable
   blob trait.
5. **Sealed-sender + unidirectional queues** hardened; delivery receipts.
6. **Mailbox redundancy + in-band migration** (§10).
7. **Stigmergic health/reputation signal** (cichlid-aligned) (§10).
8. **Settlement seam against a STUB/testnet backend** (§8.5) — prove the architecture with
   **no mainnet** and **no real value**.
9. **OPEN: edge settlement & fair-exchange design pass** (§9) — the real money-architecture
   work.
10. **Later phases:** directory/DHT findability (§6.2), UnifiedPush (§11), one real settlement
    backend, then groups (MLS) and multi-device (Sesame).

---

## 14. The one-line thesis

> **buh is communication infrastructure, not a money transmitter — and it stays that way by
> holding nothing, denominating nothing, and redeeming nothing for fiat.** The privacy thesis
> and the regulatory constraint select the same austere, non-custodial design; the only
> genuinely open problem that design creates is honest, peer-to-peer edge settlement, and that
> is the next thread to pull.
