// Thin client for the Phase-1 blind relay (`/v1`). The relay sees only opaque payloads keyed
// by a 32-byte queue id — no identity, no sender. Possession of the queue id is the entire
// capability. Requests go same-origin and are proxied to `buh-api` by Vite (see vite.config).

import { fromBase64, toBase64, toHex } from "./bytes";

export interface StoredEnvelope {
  envelope_id: string;
  payload: Uint8Array;
  received_at: string;
  expires_at: string;
}

const DEFAULT_TTL_SECONDS = 3600;

/// Push a sealed envelope to a queue. Returns the relay's envelope id.
export async function push(queueId: Uint8Array, payload: Uint8Array): Promise<string> {
  const res = await fetch(`/v1/queue/${toHex(queueId)}/envelopes`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ payload: toBase64(payload), ttl_seconds: DEFAULT_TTL_SECONDS }),
  });
  if (!res.ok) throw new Error(`relay push failed: ${res.status}`);
  return (await res.json()).envelope_id;
}

/// Pull live envelopes (oldest first), optionally long-polling up to `waitSeconds`.
export async function pull(queueId: Uint8Array, waitSeconds = 0): Promise<StoredEnvelope[]> {
  const q = waitSeconds > 0 ? `?wait=${waitSeconds}` : "";
  const res = await fetch(`/v1/queue/${toHex(queueId)}/envelopes${q}`);
  if (!res.ok) throw new Error(`relay pull failed: ${res.status}`);
  const body = await res.json();
  return body.envelopes.map((e: { envelope_id: string; payload: string; received_at: string; expires_at: string }) => ({
    envelope_id: e.envelope_id,
    payload: fromBase64(e.payload),
    received_at: e.received_at,
    expires_at: e.expires_at,
  }));
}

/// Acknowledge delivery, removing the envelope from the live queue.
export async function ack(queueId: Uint8Array, envelopeId: string): Promise<boolean> {
  const res = await fetch(`/v1/queue/${toHex(queueId)}/envelopes/${envelopeId}/ack`, {
    method: "POST",
  });
  if (!res.ok) throw new Error(`relay ack failed: ${res.status}`);
  return (await res.json()).acknowledged;
}

/// Whether the relay is reachable.
export async function health(): Promise<boolean> {
  try {
    const res = await fetch("/v1/health");
    return res.ok;
  } catch {
    return false;
  }
}
