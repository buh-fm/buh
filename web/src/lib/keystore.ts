// A device key store for the client's secret state blobs (identity seed, prekey secrets,
// ratchet sessions). Everything is sealed at rest: a passphrase is stretched with **Argon2id**
// into an AES-GCM key, and each blob is stored in IndexedDB as {iv, ciphertext}. The wasm
// facade is stateless, so this is where persistence lives — `IndexedDbKeyStore` now, a
// `TauriKeyStore` later behind the same interface (the same trait-swap discipline as the
// node's blob/settlement adapters).

import { argon2id } from "hash-wasm";
import { type IDBPDatabase, openDB } from "idb";

export interface KeyStore {
  put(key: string, value: Uint8Array): Promise<void>;
  get(key: string): Promise<Uint8Array | null>;
  delete(key: string): Promise<void>;
}

const DB_NAME = "buh";
const SEALED = "sealed";
const META = "meta";

/// Copy bytes into a fresh, concrete `ArrayBuffer` — WebCrypto wants `BufferSource` backed by
/// `ArrayBuffer`, which the generic `Uint8Array<ArrayBufferLike>` from wasm/idb doesn't satisfy.
function ab(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

interface SealedRecord {
  iv: Uint8Array;
  ct: Uint8Array;
}

export class IndexedDbKeyStore implements KeyStore {
  private constructor(
    private readonly db: IDBPDatabase,
    private readonly aesKey: CryptoKey,
  ) {}

  /// Open (or create) the store and derive its AES-GCM key from `passphrase` via Argon2id over
  /// a persistent per-device salt.
  static async open(passphrase: string): Promise<IndexedDbKeyStore> {
    const db = await openDB(DB_NAME, 1, {
      upgrade(database) {
        database.createObjectStore(SEALED);
        database.createObjectStore(META);
      },
    });

    let salt = (await db.get(META, "salt")) as Uint8Array | undefined;
    if (!salt) {
      salt = crypto.getRandomValues(new Uint8Array(16));
      await db.put(META, salt, "salt");
    }

    const raw = await argon2id({
      password: passphrase,
      salt,
      parallelism: 1,
      iterations: 3,
      memorySize: 65536, // 64 MiB
      hashLength: 32,
      outputType: "binary",
    });
    const aesKey = await crypto.subtle.importKey("raw", ab(raw), "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]);
    return new IndexedDbKeyStore(db, aesKey);
  }

  async put(key: string, value: Uint8Array): Promise<void> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt({ name: "AES-GCM", iv: ab(iv) }, this.aesKey, ab(value)),
    );
    const record: SealedRecord = { iv, ct };
    await this.db.put(SEALED, record, key);
  }

  async get(key: string): Promise<Uint8Array | null> {
    const record = (await this.db.get(SEALED, key)) as SealedRecord | undefined;
    if (!record) return null;
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ab(record.iv) },
      this.aesKey,
      ab(record.ct),
    );
    return new Uint8Array(pt);
  }

  async delete(key: string): Promise<void> {
    await this.db.delete(SEALED, key);
  }
}
