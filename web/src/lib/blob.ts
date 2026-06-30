// Thin client for the blob role (Phase 5, `doc/design.md` §3.2). Media is encrypted client-side
// under a per-file content key before upload, so the blob node stores opaque ciphertext keyed by
// `bucket` + an opaque `locator` and cannot read a byte of it. Possession of the locator is the
// entire capability. Requests go same-origin and are proxied to `buh-api` by Vite, exactly like
// the relay client.

import { toHex } from "./bytes";

/// Thrown when the node does not run the blob role (HTTP 501) — distinct so the demo can degrade
/// gracefully when pointed at a relay-only node.
export class BlobRoleUnavailable extends Error {
  constructor() {
    super("this node does not run the blob role (501)");
    this.name = "BlobRoleUnavailable";
  }
}

/// Upload opaque ciphertext to `bucket/key`. The node stores these bytes verbatim.
export async function putBlob(bucket: string, key: string, ciphertext: Uint8Array): Promise<void> {
  const res = await fetch(`/v1/blob/${bucket}/${key}`, {
    method: "PUT",
    headers: { "content-type": "application/octet-stream" },
    // Copy into a fresh ArrayBuffer so the body type is a plain BufferSource (TS 5.7's
    // Uint8Array<ArrayBufferLike> otherwise trips the BodyInit bound — same dance as keystore.ts).
    body: ciphertext.slice().buffer,
  });
  if (res.status === 501) throw new BlobRoleUnavailable();
  if (!res.ok) throw new Error(`blob put failed: ${res.status}`);
}

/// Fetch the opaque ciphertext stored at `bucket/key`.
export async function getBlob(bucket: string, key: string): Promise<Uint8Array> {
  const res = await fetch(`/v1/blob/${bucket}/${key}`);
  if (res.status === 501) throw new BlobRoleUnavailable();
  if (!res.ok) throw new Error(`blob get failed: ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

/// Mint an opaque, content-free blob locator (32 random bytes, hex). The sender picks this and
/// sends it — with the content key — only through the encrypted channel.
export function randomLocator(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(32)));
}
