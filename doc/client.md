# buh - Secure Client Architecture

> Companion to `doc/design.md`. That document describes the **platform fundamentals** - the
> blind relay/mailbox node, the blob store, the economic model - which are already under
> construction. **This** document describes the **client** buh should be reaching for: where
> the cryptographic intelligence lives, how it is delivered, and - most importantly - why
> *how the client is delivered* is itself part of the threat model.

**Status:** architecture target, ahead of the client build
**Audience:** the client implementer. Where a guarantee is real, this document says so; where the
design *cannot* deliver a guarantee, it says that too (see §11), so nothing here promises the
implementer - or, through them, the user - protection the architecture cannot keep.
**Relationship to design.md:** design.md owns the node/platform; this doc owns the client. The
shared crypto core (`buh-crypto`) is the seam between them.

---

## 1. The premise: delivery is part of the threat model

buh's whole design removes trust from the node - the relay is blind, holds only
`queue_id → envelope_refs`, and all identity, key agreement, ratcheting, and envelope sealing
live in the client (`buh-crypto`). That is the right place for it.

But it relocates the trust problem rather than eliminating it. **If the node can betray
nothing, then the client is the only thing left that can.** And a client is only as
trustworthy as the channel that delivered its code. A perfectly written `buh-crypto` is worth
nothing if the user runs a copy that was swapped out underneath them between the time it was
audited and the time it ran.

So the client architecture is organised around a single distinction that the rest of this
document elaborates:

> **Convenience tier** - code re-fetched on every use from infrastructure that can change it
> silently. Good for trying buh. Structurally unable to make strong guarantees.
>
> **Security tier** - code installed once as a signed, verifiable build that does not change
> underneath the user. The only tier suitable for messaging that actually needs to be secure.

These two tiers **share one Rust core** and differ only in delivery. Conflating them - letting
"it's just a static build" lodge in everyone's head - is the failure mode this document
exists to prevent.

**The argument recurses - keep applying it.** "The running code is only as trustworthy as the
channel that delivered it" is not a fact about *one* artifact; it is a lens that must be turned
on every input the client trusts. The same reasoning lands on at least four more surfaces, each
treated in its own section:

- the **invite channel** that bootstraps who a contact *is* and which nodes to trust (§7) -
  trust-on-first-use, undetectable MITM without out-of-band verification (§4);
- the **host RNG** the crypto draws keys from - on the web the serving origin controls it (§6.2);
- the **platform shell** that holds the key and renders plaintext - un-audited but fully inside
  the trusted computing base (§3, §5);
- the **build pipeline and dependency graph** that produced the artifact in the first place (§8).

Wherever this document earlier said "the host can swap the bundle," read it as the general
case: *something upstream of the running code can substitute what the user trusts, and the only
defence is to make that substitution either impossible or observable.*

---

## 2. Trust tiers

| | **Convenience tier** | **Security tier** |
|---|---|---|
| Examples | Web app on buh.fm; web apps any operator hosts on their own domain | Android/iOS store apps (with transparent CI); signed desktop releases; **source build on one's own hardware** |
| Delivery | Re-fetched per page load from a web origin + CDN | Installed once; updated through a signed, auditable channel |
| Who can alter the running code | The host, the CDN, anyone who compromises either, per load, silently | Whoever holds signing keys - **and**, for store apps, the store operator who re-signs and delivers - but a change is a discrete event, observable if (and only if) someone is monitoring (§8) |
| Code identity verifiable by user? | No (no first-use to pin; every visit is a fresh fetch) | Yes for desktop/source builds; **partially** for store apps - see the iOS caveat below |
| Recommended use | Sandboxing / dogfooding / evaluating buh utility | Real, sensitive messaging |
| UI stance | **Carries an explicit in-product warning** (see §6.3) | Recommended path; verification instructions provided |

The operator reality buh is built for: **buh.fm will host a convenience web app, and other
operators may host their own on their own domains/infra.** That is healthy decentralisation,
but it multiplies the convenience-tier surface - every operator's web origin is independently
trusted-per-load by its users. The mitigation is not to forbid it (it is genuinely useful for
adoption) but to mark it honestly in the UI and route anyone with a real threat model to the
security tier. Operator hardening (§6.2) should be a **baseline**, not an option, precisely
because a self-hosting operator's choices are someone else's risk.

If, and only if, buh can land **Android/iOS apps in trusted app stores with transparent CI**,
those become a recommended security-tier route alongside **desktop releases** and
**source builds on one's own hardware** - with one honest caveat:

> **Store apps put the store operator in the TCB.** Transparent CI proves what was *submitted*,
> not what the store *delivers and runs*. Apple and Google can refuse, pull, or be compelled to
> deliver a targeted build, and on **iOS** the App Store re-signs/re-encrypts the binary
> (FairPlay), so a user cannot reproduce-and-compare the *delivered* artifact on device. The
> achievable property for store apps is therefore "public CI provenance + community monitoring
> of the *submitted* build," not user-side bit-for-bit verification of the *running* one. Treat
> iOS-via-store as **strong key custody with a verifiability ceiling**, not as equal to a
> self-verified desktop or source build.

---

## 3. One core, several shapes: `buh-crypto`

The workspace already establishes the right shape: `buh-crypto` is the client crypto core
(PQ identity, PQXDH, Double Ratchet, wire codec) that **compiles to WASM and that the node
never links.** Every client delivery is a different compile target of that one crate plus a
thin platform shell.

```
                       ┌────────────────────────────┐
                       │        buh-crypto          │   one audited Rust core
                       │  PQ identity (ML-DSA)       │   PQXDH (X25519+ML-KEM-768)
                       │  Double Ratchet (+SPQR path)│   wire codec, envelope sealing
                       │  blob content-key crypto    │   key-storage as an injected trait
                       └──────────────┬─────────────┘
              ┌───────────────────────┼────────────────────────┐
              ▼                       ▼                         ▼
      WASM (wasm-bindgen)     native ARM64 + UniFFI      native lib (desktop)
              │                       │                         │
   ┌──────────┴─────────┐   ┌─────────┴─────────┐    ┌──────────┴──────────┐
   │ Vite React-SWC-TS  │   │ Android (Kotlin)  │    │ Desktop shell        │
   │ web app            │   │ iOS (Swift)       │    │ (native UI, no       │
   │ CONVENIENCE TIER   │   │ SECURITY TIER*    │    │  webview) SECURITY   │
   └────────────────────┘   └───────────────────┘    └─────────────────────┘
                              *if store + transparent CI
```

The discipline is the same one used everywhere else in the project: **one source of truth,
multiple compile targets, thin platform bindings.** The crypto is written and audited once; the
shells carry no cryptographic logic of their own.

**Two honesties the implementer must hold onto, or "audited once" overpromises:**

1. **"Audited once" is about the *source*, not the *binary per target*.** WASM, native ARM64,
   and desktop native are distinct builds with distinct codegen, distinct `getrandom` backends
   (this project already had to reconcile getrandom's `wasm_js` backend against native - see the
   build history), and distinct dependency-feature unification. A source audit is necessary but
   does not certify each target's binary. Each target needs its own reproducibility check (§8),
   and security-relevant invariants - **constant-time execution** above all - must be *tested*
   per target, because `wasm-opt`, LTO, and a JIT can erase the constant-time property the
   source intended. Assume nothing about timing behaviour survives optimisation until measured.
2. **The shell is not in the audited core, but it is in the TCB.** "Carries no cryptographic
   logic" is true and useful, but the shell still holds (or brokers) the key, decides what gets
   signed, and renders the plaintext the human reads. A compromised shell does not need to break
   `buh-crypto`; it operates it (see §5). The security-tier TCB is therefore
   **core + shell + FFI glue + OS**, not `buh-crypto` alone.

### Why native (not WASM) on mobile

Mobile is **not** a place to embed a WASM runtime. The core is Rust, and Rust compiles to
native ARM64 directly; routing Rust → WASM → embedded-runtime → native would add a runtime,
pay an interpreter penalty on iOS (which forbids third-party JIT), and run the crypto a step
removed from the metal - all to avoid what Rust already does for free. Instead:

- **Android:** `buh-crypto` → `.so`, called over JNI, with **UniFFI** generating the Kotlin
  bindings from the Rust interface (no hand-written JNI).
- **iOS:** `buh-crypto` → static lib, called over a Swift bridge, **UniFFI** generating the
  Swift bindings. Native ARM64; the JIT ban is irrelevant because nothing is JITed.

WASM stays the **web** answer specifically; native is the **mobile and desktop** answer.

---

## 4. What the client is responsible for

Because the node is blind, the client carries essentially the entire protocol. `buh-crypto`
(portable) plus the shell (platform) must between them own:

- **Identity** - the user-held PQ keypair (ML-DSA, FIPS 204). The user *is* their key.
- **Handshake** - PQXDH-grade hybrid key agreement (X25519 + ML-KEM-768, FIPS 203) against a
  contact's signed prekey bundle.
- **Ratchet** - Double Ratchet; symmetric chains are already PQ-safe, with the wire format
  versioned so the **PQ rekey path (Signal's AGPL SPQR ratchet)** can land later without a
  break. (This is one of the reasons the project is AGPL-3.0-only.)
- **Envelope sealing** - sealed-sender semantics so the relay never learns the sender.
- **Contact verification** - out-of-band comparison of an identity fingerprint / safety number
  between two users. **This is not optional.** First contact via an invite is trust-on-first-use
  (§7): the invite is signed by an identity key the recipient has never seen, so a
  man-in-the-middle on the *invite delivery channel* can substitute their own prekeys and node
  CAs and sit in the conversation undetected from message one. A fingerprint both parties can
  compare over a second channel (read aloud, scanned, etc.) is the only thing that catches this
  after the fact. The client must surface it and make it routine.
- **Entropy discipline** - keys are only as good as the randomness behind them. The core should
  accumulate its own CSPRNG state and mix the host RNG in as *one untrusted input* rather than
  trusting a single `getrandom`/`crypto.getRandomValues` call outright. This raises the cost of
  a backdoored host RNG on native (multiple, harder-to-control sources). **It does not solve the
  web tier**, where the serving origin controls the entire JS environment including the RNG
  (§6.2, §11) - that is a structural limit, not a hardening gap.
- **Blob crypto** - per-file content key (XChaCha20-Poly1305); encrypt once, upload opaque
  ciphertext to a blob node, fold `{locator + content key}` into the envelope; fetch and
  decrypt lazily on receive.
- **Queue management** - holding the user's set of unidirectional queues and contacts.
- **Node CA pinning** - pinning each node's self-served CA, carried in the invite's **queue
  descriptor** (see §7); the client, not a central PKI, decides which node identities to trust.
- **Redundancy & migration** - maintaining N redundant mailboxes on independent nodes, and
  honouring in-band signed "I've moved to node X" messages. A migration re-points which *nodes*
  the user trusts, so it is a privileged operation: it must be authenticated by a fresh
  **identity-key** signature (not merely the session/ratchet key), rate-limited, and surfaced
  for user confirmation - otherwise a single session compromise becomes permanent traffic
  redirection (§7).
- **Identity backup / recovery / multi-device** - an explicit, deferred, per-deployment
  decision, *not* a default, because it is in direct tension with hardware-held non-extractable
  keys (§5). The implementer must choose a position consciously; "we never thought about it" is
  how users lose their identity to a dropped phone.

Everything in the protocol group (identity, handshake, ratchet, sealing, blob crypto, wire
codec, contact-verification math, entropy accumulation) belongs in **`buh-crypto`** so it is
written and audited once across all tiers. The shell owns UI, transport plumbing, local storage
orchestration, push wakeups, and the platform key-storage implementation (§5).

---

## 5. Key custody - an injected trait, not core-resident

The single most sensitive decision in a client is *where the identity private key lives*. This
must **not** be hard-coded into the portable core, because the right answer is
platform-specific and hardware-backed where possible:

- **iOS:** Secure Enclave.
- **Android:** StrongBox / hardware-backed Keystore.
- **Desktop:** TPM where available; OS keychain otherwise.
- **Web (convenience):** non-extractable WebCrypto keys / IndexedDB at best - and this is
  precisely one of the reasons the web tier cannot make security-tier promises (see §6).

So key storage is modelled as an **injected trait** that `buh-crypto` depends on and each
platform implements - the same swappable-backend shape already used for `MailboxRepo`,
`BlobStore`, and `SettlementBackend` in the core. The portable core performs the protocol; it
asks the platform to *hold*, *use*, and *attest* key material without ever requiring the raw
private key to cross back into portable code where hardware backing exists.

This draws a clean line across the FFI boundary: **protocol logic crosses into the core; raw
hardware-held key material does not.**

**What hardware backing does and does not buy you - say it plainly:**

- It prevents **extraction** of the key. It does **not** prevent **use** of the key. A
  compromised shell cannot read the Secure Enclave / StrongBox private key, but it can ask the
  enclave to *sign* and *decrypt* arbitrarily for as long as it runs - an unlimited oracle. For
  a messenger that means decrypting all traffic and impersonating the user during the
  compromise. Non-extractable key custody narrows the blast radius (no permanent key theft, no
  offline attack after the fact); it does not make a compromised shell harmless. This is why §3
  insists the shell is in the TCB.
- On the **web**, at-rest sealing (the Argon2id-derived key over IndexedDB the reference client
  uses) protects state against **device theft on an honest deployment**. It is **worthless
  against a malicious origin**, because the origin also runs the passphrase entry and the unseal
  path - it captures the passphrase and unwraps everything. Do not present web at-rest sealing as
  protection against the serving origin; it isn't.
- **Backup / recovery / multi-device cuts against non-extractability.** If the key cannot leave
  the enclave, a lost device is a lost identity and a second device is impossible without some
  key-sharing scheme. The candidate resolutions - a user-controlled encrypted export
  (sacrificing pure non-extractability by choice), per-device identity keys with a Sesame-style
  multi-device layer, or social/seed recovery - are real engineering with real tradeoffs.
  design.md defers multi-device; this document's only requirement is that the implementer pick a
  position **on purpose** and tell the user what device loss means for them.

Deciding exactly which key material is hardware-held versus held in the portable core (where no
enclave exists, e.g. some desktop and all web) is an explicit per-platform decision, not a
default.

---

## 6. Convenience tier: the web/WASM client

### 6.1 It hosts trivially - that part is true

A `buh-crypto` WASM bundle plus the Vite (React-SWC-TS) app is a set of static assets. It
serves from buh.fm, any operator's domain, GitHub Pages, Cloudflare Pages, S3+CDN - no server
logic required. `application/wasm` MIME is handled by all the obvious hosts; a CDN that gets it
wrong is worked around with `WebAssembly.instantiate(arrayBuffer)` instead of the streaming
variant.

One operational caveat if the WASM build ever uses **threads** (`wasm-bindgen-rayon`, a
threaded crypto pool): `SharedArrayBuffer` requires cross-origin isolation, i.e. the
`Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`
response headers. **GitHub Pages cannot set custom response headers** (so threaded WASM needs
the `coi-serviceworker` shim there); Cloudflare Pages and Netlify can. ML-KEM-768 / ML-DSA do
**not** need threads, so single-threaded WASM is fine and GH Pages stays viable - but this is a
trap worth knowing before someone reaches for a thread pool. Note also that a service worker is
itself a persistent interception layer the origin controls (§6.2): reach for the shim only when
genuinely needed.

### 6.2 Why it is structurally weaker - not fixably so

The web tier's weakness is **not** a hardening gap that more effort closes. It is structural.
The serving origin runs arbitrary code in the user's session on every load, so it sits upstream
of *everything*:

- **No first use to anchor trust.** Every visit re-fetches the code. There is no
  trust-on-first-use, no installed artifact to compare against - so the host, the CDN, or
  anyone who compromises either can serve a key-exfiltrating build to one user, once, and
  nobody else ever sees it. Targeted, silent, per-load.
- **The origin controls the RNG.** Key generation draws from `crypto.getRandomValues` via the
  host JS environment. A malicious origin shims it to return predictable values and backdoors
  every key the core mints - **without touching the WASM bundle at all**, so SRI hashes,
  reproducible-build comparison, and CSP all pass while the keys are broken. The core's entropy
  accumulation (§4) raises the bar but cannot win here: the origin owns every source the JS
  environment exposes. This is the sharpest single example of why the tier is structural.
- **The origin controls the unseal path.** As in §5, at-rest sealing is moot against the host.
- **Weaker key custody.** No Secure Enclave / StrongBox equivalent; best case is
  non-extractable WebCrypto keys, which still live inside a document the served code fully
  controls - and "non-extractable" only blocks *export*, not *use* as an oracle.
- **Large, mutable TCB.** The browser, every page-load fetch, the serving origin, the JS
  dependency tree compiled into the bundle (a poisoned npm transitive dep is faithfully - even
  reproducibly - compiled in), service workers, and browser extensions are all inside the
  trusted computing base, and all mutable.

Partial hardening is still worth doing, because it raises the cost of *broad* (vs. *targeted*)
attacks: Subresource Integrity (SRI) hashes on the bundle, a **reproducible build** whose
hashes a third party can publish and a user can in principle check, COOP/COEP isolation, strict
CSP, dependency pinning/auditing, and pinning. These should be **baseline for any operator**,
not optional, and the project should ship a secure-by-default Vite/headers config so a
self-hosting operator gets them for free. But none of this defeats a malicious *origin*, because
the origin chooses which (possibly SRI-consistent) bundle to serve, controls the RNG, and can
serve a different build to a single targeted user. **Reproducibility lets the diligent catch
broad tampering; it cannot make a re-fetched-per-load web app equal to an installed signed
build.**

### 6.3 The required UI warning - and what it is not

The web client ships with an **explicit, prominent in-product warning**: that the web app is for
**sandboxing / dogfooding / evaluating buh's utility**, not for messaging that needs to be
secure, and that real security lives in the installed, verifiable builds (store app with
transparent CI, signed desktop release, or source build on one's own hardware). This warning is
part of the product and applies equally to buh.fm and to any operator's self-hosted web app.

Be honest with yourself about its scope: **the warning is advisory UX, not a security control.**
It protects users of an *honest* convenience deployment from *misunderstanding* the tier they are
in. It does nothing against the actual threat - a malicious origin controls the code and simply
omits the warning. State it because honesty is the whole posture of this tier, not because it
defends anyone against a hostile host.

---

## 7. Node trust & CA pinning from invites

The client's trust in a *node* is established without any central PKI, consistent with the
platform's decentralised self-served PQ-mTLS (X25519MLKEM768) under per-node CAs. The
mechanism is already part of the protocol: a node's CA is **carried in the invite's queue
descriptor**, and the client **pins** it. First contact (the out-of-band signed invite) thus
bootstraps both the contact's prekey bundle *and* the set of node CAs the client will trust for
that contact's queues. Migration ("I've moved to node X") arrives in-band over the existing
encrypted channel and updates the pinned set.

Two honesties, both instances of the §1 recursion:

- **The pin is only as good as the invite channel.** Bootstrapping prekeys *and* node CAs from
  the invite means a man-in-the-middle on invite delivery substitutes both at once and becomes
  an undetectable relay for that contact. The invite is self-signed by an identity the recipient
  has never seen, so its signature proves internal consistency, not authenticity. The only
  defence is the out-of-band **contact verification** of §4; the client must treat an unverified
  contact as exactly that, and make verification easy enough that users actually do it.
- **The pin is only as trustworthy as the client enforcing it** - back to §1. An installed,
  verified client enforces pinning you can rely on; a re-served-per-load web client enforces
  whatever the last fetch told it to.

And the migration path is privileged: re-pinning the trusted node set from an in-band message
must require a fresh **identity-key** signature, be rate-limited, and be user-confirmable
(§4), so a stolen session cannot silently redirect all future traffic to an attacker's node.

---

## 8. Code identity & verification - the security tier's whole point

What makes the security tier *secure* is that the user (or someone they trust) can verify
**which code is running**. The toolkit - stated as *mechanisms to build*, not properties to
assume:

- **Reproducible builds - as a checked mechanism, not a label.** Source → bit-identical
  artifact is the keystone; without it, signing only proves *who* built it, not *what* they
  built. But Rust/WASM reproducibility is not free: path remapping (`--remap-path-prefix`),
  `wasm-opt` and LTO/linker nondeterminism, build-script and timestamp leakage, and per-target
  feature unification all break bit-identity if ignored. So the deliverable is not "we have
  reproducible builds" but **CI that double-builds each target on independent infrastructure and
  diffs the artifacts**, failing if they differ - and a per-target check, since §3 notes targets
  diverge.
- **Binary transparency log.** "A malicious update is an after-the-fact-auditable event" is only
  true if *someone is watching*. Publish releases (and their reproducible hashes + provenance)
  to an **append-only, publicly monitored transparency log** (sigstore/rekor- or CT-style), so a
  *targeted* signed build is detectable by monitors rather than only by the victim who happens to
  compare hashes. Without a log, "observable" quietly means "observable in principle by someone
  who isn't looking."
- **Transparent CI + signing.** Builds from a public, auditable pipeline with build
  provenance/attestation; releases signed; updates delivered as discrete events. For **store
  apps**, remember the §2 caveat: this attests the *submitted* build, and on iOS the store
  re-signs the *delivered* one - provenance + monitoring of submissions is the achievable
  property, not user-side verification of the running binary.
- **Build-time supply chain.** Reproducibility detects output divergence; it does **not** detect
  a faithfully-compiled malicious dependency (crates.io or npm). Pin and audit dependencies,
  prefer vendoring for release builds, and keep the JS tree as small as the convenience tier can
  bear - it is in that bundle's TCB.
- **Source build on own hardware.** The strongest tier: the user compiles `buh-crypto` and the
  shell themselves on hardware they control, trusting only the source (which is AGPL - they can
  read it) and their own toolchain. Note even this, and every installed tier, has a
  **first-acquisition** trust-on-first-use moment: an artifact verified *after* first run already
  ran. Only verify-before-first-run (or build-from-source) closes it; the implementer should make
  pre-run verification the documented default for desktop releases.

Per-tier verification reality:

| Tier | Can a user verify the running code? | How |
|---|---|---|
| Web (convenience) | Not meaningfully | Re-fetched per load; origin controls RNG + unseal; at best broad-tamper detection via reproducible-build hash comparison |
| Store app (Android) + transparent CI | Mostly, with effort | Reproducible build + public CI provenance + transparency-log monitoring of submissions + signature; store operator in TCB |
| Store app (iOS) + transparent CI | Partially | Provenance + monitoring of the *submitted* build only; App Store re-signing blocks on-device bit comparison of the *delivered* build |
| Signed desktop release | Yes, with effort | Reproducible build + signature + transparency log; user verifies hash **before first run** |
| Source build on own hardware | Yes, directly | They built it from source they can read |

---

## 9. Build targets summary

> **Desktop note - no webview shells.** Tauri (or any system-webview shell) is a fine default
> in the project's *general* desktop conventions, but it is explicitly **not** used for buh
> clients. A webview shell renders the UI in an OS-managed browser engine
> (WebView2 / WebKitGTK / WKWebView) that is updated separately and outside the app's
> control - pulling a mutable browser engine into the TCB and reintroducing the exact
> "UI is served content in a browser engine" property the security tier exists to escape. It
> also fractures build auditability: a reproducible build would cover the Rust side but not the
> webview the OS ships underneath it. The desktop security-tier client therefore uses a
> **true native UI** over the same `buh-crypto` lib, with no webview in the trusted path.


| Target | Core | Shell | Tier | Notes |
|---|---|---|---|---|
| Web | `buh-crypto` → WASM (wasm-bindgen) | Vite React-SWC-TS | Convenience | Static-hostable; warning UI; weak key custody; origin controls RNG/unseal; no per-load verifiability |
| Android | `buh-crypto` → `.so` via UniFFI | Kotlin | Security* | *if store + transparent CI; StrongBox/Keystore custody; store operator in TCB; mostly verifiable via provenance + transparency log |
| iOS | `buh-crypto` → static lib via UniFFI | Swift | Security* | *if store + transparent CI; Secure Enclave custody; native (no WASM, JIT ban moot); **verifiability ceiling** - App Store re-signing blocks on-device reproducible comparison |
| Desktop | `buh-crypto` → native lib | Native UI shell (no webview) | Security | Signed reproducible release; verify hash before first run; TPM/keychain custody |
| Source build | `buh-crypto` from source | Any of the above | Security (strongest) | User-compiled on own hardware; trusts only AGPL source + own toolchain |

Across all tiers, the security-tier TCB is **core + shell + FFI + OS** (§3, §5); hardware key
custody narrows the blast radius of a shell compromise but does not remove the shell from the
TCB.

---

## 10. Implementation ordering (client)

1. **`buh-crypto` core:** PQ identity (ML-DSA), PQXDH (X25519 + ML-KEM-768), Double Ratchet
   with wire-versioning reserved for the SPQR PQ-rekey path, wire codec, envelope sealing, blob
   content-key crypto, **contact-fingerprint derivation**, and **in-core entropy accumulation**.
   Key storage defined as an **injected trait**. Add constant-time tests that run per target.
2. **Reference web client (convenience):** WASM + Vite React-SWC-TS; out-of-band invite flow
   **with a contact-verification step**; CA pinning from queue descriptors; the §6.3 warning UI
   from day one; the secure-by-default headers/SRI/CSP config operators inherit. This is the
   fastest path to dogfooding the core end-to-end.
3. **Desktop security-tier client:** native `buh-crypto` lib + native UI shell; reproducible
   build (double-built and diffed in CI) + signing + transparency-log publication;
   verify-before-first-run docs; TPM/keychain key storage. First *trustworthy* delivery.
4. **Mobile via UniFFI:** Android (`.so`/JNI/Kotlin, StrongBox) then iOS (static lib/Swift,
   Secure Enclave); pursue store listings with transparent CI to earn the security-tier
   recommendation - with the iOS verifiability ceiling documented for users, not hidden.
5. **Verification & recovery infrastructure:** publish reproducible-build hashes, CI provenance,
   and the transparency log; document per-tier verification steps; and **decide and document the
   identity backup / recovery / multi-device position** (§5) before users have identities to
   lose.

---

## 11. Limits of the design - what it cannot achieve

The implementer should be able to point at these in a sentence when a user asks "is buh secure?"
None is a TODO; each is a property of the architecture or its environment. Hiding them would make
this document the kind of overclaim §1 exists to prevent.

- **The web/convenience tier cannot be made security-grade.** A malicious origin controls the
  code, the RNG, and the unseal path per load (§6.2). Mitigations raise the cost of *broad*
  attacks; nothing in-tier stops a *targeted* one. Route real threat models to the security tier.
- **Store delivery has a verifiability ceiling**, hardest on iOS (re-signing blocks on-device
  reproducible comparison), and puts the store operator in the TCB (§2, §8).
- **A compromised shell is an oracle.** Hardware key custody prevents key *theft*, not key *use*;
  while a malicious shell runs it can decrypt and impersonate (§5). The security tier minimises,
  but cannot eliminate, trust in the shell + OS.
- **First contact is trust-on-first-use.** The invite proves consistency, not authenticity;
  undetectable MITM is possible until users do the out-of-band fingerprint check (§4, §7). buh
  can make verification easy; it cannot make users do it.
- **Push notifications reintroduce a metadata observer.** APNs/FCM see device + timing,
  re-centralising metadata the blind relay was designed to avoid. Prefer **UnifiedPush** where
  available and treat APNs/FCM as a disclosed leak; this is a platform constraint, not a buh bug.
- **Metadata and traffic analysis are largely out of scope here.** The client owns redundant-
  mailbox fan-out and polling, whose timing/pattern is a fingerprint; cover-traffic and jitter
  are future work, not current guarantees.
- **Identity loss is possible by design.** Non-extractable keys mean a lost device can mean a
  lost identity until a recovery position is chosen (§5). Tell users plainly.
- **Side channels survive optimisation unless tested.** Constant-time source is not constant-time
  binary after `wasm-opt`/JIT/LTO; this is mitigated by per-target testing (§3), not assumed.

---

## 12. One-line thesis

> **buh moves all trust into the client, so the client's *delivery channel* is now the threat
> surface - and so are the invite channel, the host RNG, the platform shell, and the build
> pipeline it recurses into.** One audited Rust core (`buh-crypto`) ships in two trust classes:
> a re-fetched-per-load web app that is honest about being a convenience/dogfooding tool, and
> installed, signed, reproducible, transparency-logged builds - store apps with transparent CI
> (within their verifiability ceiling), desktop releases, or source builds on one's own
> hardware - that are the only path for messaging that actually needs to be secure. Where the
> design cannot deliver a guarantee, the client says so (§11) rather than implying one.
