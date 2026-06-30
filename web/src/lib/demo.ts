// The Phase-4 milestone: a sealed 1:1 text message travelling Alice ↔ Bob through the real
// blind relay, end-to-end encrypted, with every secret persisted through the KeyStore.
//
// One page plays both parties (Alice and Bob), so the whole path is observable: identity →
// signed invite → PQXDH handshake → Double Ratchet, with the ciphertext going over the wire
// to `buh-api` and back. The relay only ever sees opaque payloads on opaque queues.

import {
  acceptSession,
  createInvite,
  decryptMessage,
  encryptMessage,
  generateIdentity,
  identityPublicKey,
  initiateSession,
  parseInvite,
  publishablePrekeyBundle,
} from "./crypto";
import { fromHex, isAllZero, randomQueueId, toBase64, toHex } from "./bytes";
import type { KeyStore } from "./keystore";
import * as relay from "./relay";

const enc = new TextEncoder();
const dec = new TextDecoder();

export interface RelayEnvelopeView {
  queue: string;
  envelopeId: string;
  payloadPreview: string;
  bytes: number;
}

export interface DemoResult {
  inviteUri: string;
  aliceFingerprint: string;
  bobFingerprint: string;
  aliceDecrypted: string;
  bobDecrypted: string;
  relayView: RelayEnvelopeView[];
  /// The queue node's CA fingerprint carried in the invite (hex), or "" when unpinned (dev).
  caFingerprint: string;
  /// Whether the relay client verified the pinned CA against the node it talked to.
  caPinVerified: boolean;
}

const fingerprint = (idPub: Uint8Array) => toHex(idPub).slice(0, 16);

function view(queue: Uint8Array, e: relay.StoredEnvelope): RelayEnvelopeView {
  return {
    queue: toHex(queue).slice(0, 16),
    envelopeId: e.envelope_id,
    payloadPreview: `${toBase64(e.payload).slice(0, 44)}…`,
    bytes: e.payload.length,
  };
}

export async function runDemo(
  store: KeyStore,
  log: (line: string) => void,
): Promise<DemoResult> {
  const relayView: RelayEnvelopeView[] = [];

  // --- Alice sets up an identity + prekey bundle and publishes an invite. ---
  log("Alice: generating identity + prekey bundle…");
  const aliceId = generateIdentity();
  await store.put("alice/identity", aliceId);
  const aliceMaterial = publishablePrekeyBundle(aliceId);
  await store.put("alice/secrets", aliceMaterial.secrets);
  await store.put("alice/bundle", aliceMaterial.bundle);
  const aliceQueue = randomQueueId();
  await store.put("alice/queue", aliceQueue);

  const nonce = crypto.getRandomValues(new Uint8Array(16));
  // The invite pins the queue node's CA. When the node serves PQ-mTLS it advertises its real CA
  // fingerprint on /v1/health; in plain dev/loopback mode there is no CA, so the field stays
  // zero (an explicit "unpinned" marker the client treats as inert).
  const advertisedCa = await relay.nodeCaFingerprint();
  const caFingerprint = advertisedCa ? fromHex(advertisedCa) : new Uint8Array(32);
  log(
    advertisedCa
      ? `Alice: pinning node CA ${advertisedCa.slice(0, 16)}… in the invite.`
      : "Alice: node serves plain HTTP (dev) — invite carries an unpinned CA placeholder.",
  );
  const inviteUri = createInvite(
    aliceId,
    aliceQueue,
    "proxied:/v1",
    caFingerprint,
    aliceMaterial.bundle,
    nonce,
    Date.now() + 86_400_000,
  );
  log(`Alice: invite created (${inviteUri.length} chars).`);

  // --- Bob receives the invite out-of-band, verifies it, and opens a session. ---
  log("Bob: parsing + verifying invite…");
  const parsed = parseInvite(inviteUri); // throws if the signature/bundle don't verify

  // Bob makes the relay client's TLS trust decision: pin the CA fingerprint the verified invite
  // carries, then confirm the node he is about to talk to presents it. (Native clients enforce
  // this at the TLS layer; the browser checks the node's advertised fingerprint — see relay.ts.)
  const caFingerprintHex = toHex(parsed.ca_fingerprint);
  let caPinVerified = false;
  if (!isAllZero(parsed.ca_fingerprint)) {
    relay.pinCa(caFingerprintHex);
    caPinVerified = await relay.verifyPinnedCa(); // throws on a genuine CA mismatch
    log(`Bob: CA pin ${caPinVerified ? "verified" : "inert (dev node)"} for ${caFingerprintHex.slice(0, 16)}…`);
  } else {
    log("Bob: invite carries no CA pin (dev node) — skipping TLS trust check.");
  }

  const bobId = generateIdentity();
  await store.put("bob/identity", bobId);
  const bobQueue = randomQueueId();
  await store.put("bob/queue", bobQueue);

  log("Bob: PQXDH handshake (X25519 + ML-KEM-768) + first ratchet message…");
  const initiated = initiateSession(bobId, parsed.bundle);
  await store.put("bob/session", initiated.session);
  const bobToAlice = encryptMessage(initiated.session, enc.encode("hello alice — bob here"));
  await store.put("bob/session", bobToAlice.session);

  // Bob delivers the handshake then the ciphertext to Alice's queue, through the relay.
  log("Bob → relay: push handshake + ciphertext to Alice's queue…");
  await relay.push(parsed.queue_id, initiated.initial_message);
  await relay.push(parsed.queue_id, bobToAlice.message);

  // --- Alice pulls from the relay, completes the handshake, and decrypts. ---
  log("Alice ← relay: pull queue (long-poll)…");
  const inbound = await relay.pull(aliceQueue, 5);
  if (inbound.length < 2) throw new Error(`expected 2 envelopes, got ${inbound.length}`);
  inbound.forEach((e) => relayView.push(view(aliceQueue, e)));

  const aliceSecrets = await store.get("alice/secrets");
  const aliceBundle = await store.get("alice/bundle");
  if (!aliceSecrets || !aliceBundle) throw new Error("alice key material missing");

  log("Alice: accept session + decrypt…");
  let aliceSession = acceptSession(aliceSecrets, aliceBundle, inbound[0].payload);
  const opened = decryptMessage(aliceSession, inbound[1].payload);
  aliceSession = opened.session;
  await store.put("alice/session", aliceSession);
  const aliceDecrypted = dec.decode(opened.plaintext);
  for (const e of inbound) await relay.ack(aliceQueue, e.envelope_id);

  // --- Alice replies; Bob pulls and decrypts. ---
  log("Alice → relay: push reply to Bob's queue…");
  const aliceToBob = encryptMessage(aliceSession, enc.encode("hi bob — got it, sealed end-to-end"));
  await store.put("alice/session", aliceToBob.session);
  await relay.push(bobQueue, aliceToBob.message);

  log("Bob ← relay: pull + decrypt reply…");
  const reply = await relay.pull(bobQueue, 5);
  if (reply.length < 1) throw new Error("expected Bob's reply");
  reply.forEach((e) => relayView.push(view(bobQueue, e)));
  const bobSession = await store.get("bob/session");
  if (!bobSession) throw new Error("bob session missing");
  const openedReply = decryptMessage(bobSession, reply[0].payload);
  await store.put("bob/session", openedReply.session);
  const bobDecrypted = dec.decode(openedReply.plaintext);
  for (const e of reply) await relay.ack(bobQueue, e.envelope_id);

  log("Done — message sealed end-to-end through the blind relay.");

  return {
    inviteUri,
    aliceFingerprint: fingerprint(parsed.identity_public_key),
    bobFingerprint: fingerprint(identityPublicKey(bobId)),
    aliceDecrypted,
    bobDecrypted,
    relayView,
    caFingerprint: isAllZero(parsed.ca_fingerprint) ? "" : caFingerprintHex,
    caPinVerified,
  };
}
