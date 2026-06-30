// Small byte/encoding helpers shared by the relay client and demo.

/// Lowercase hex, as the relay expects queue ids in the URL path.
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/// Standard (non-URL-safe) base64 — the encoding the relay uses for envelope payloads.
export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/// 32 cryptographically-random bytes — used here to mint opaque queue ids.
export function randomQueueId(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}
