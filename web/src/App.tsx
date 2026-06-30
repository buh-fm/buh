import { useEffect, useRef, useState } from "react";
import { version } from "./lib/crypto";
import { type DemoResult, runDemo } from "./lib/demo";
import { IndexedDbKeyStore } from "./lib/keystore";
import { health } from "./lib/relay";

const mono: React.CSSProperties = { fontFamily: "ui-monospace, monospace" };

export default function App() {
  const [relayUp, setRelayUp] = useState<boolean | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const [result, setResult] = useState<DemoResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const store = useRef<IndexedDbKeyStore | null>(null);

  useEffect(() => {
    health().then(setRelayUp);
  }, []);

  async function run() {
    setRunning(true);
    setError(null);
    setResult(null);
    setLog([]);
    try {
      if (!store.current) {
        store.current = await IndexedDbKeyStore.open("buh-demo-passphrase");
      }
      const append = (line: string) => setLog((l) => [...l, line]);
      setResult(await runDemo(store.current, append));
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", maxWidth: 760, margin: "2.5rem auto", padding: "0 1rem" }}>
      <h1>buh — end-to-end through a blind relay</h1>
      <p>
        buh-crypto v{version()} · relay{" "}
        <strong style={{ color: relayUp ? "green" : relayUp === false ? "crimson" : "gray" }}>
          {relayUp == null ? "checking…" : relayUp ? "reachable" : "unreachable (start buh-api)"}
        </strong>
      </p>
      <p style={{ color: "#555" }}>
        One page plays Alice and Bob. Alice publishes a signed invite; Bob verifies it, runs the
        PQXDH handshake (X25519 + ML-KEM-768) and Double Ratchet, and a sealed text message
        travels each way <strong>through the real relay</strong>. Every secret is persisted via an
        Argon2id-sealed IndexedDB key store.
      </p>

      <button type="button" onClick={run} disabled={running || relayUp === false} style={{ padding: "0.5rem 1rem", fontSize: "1rem" }}>
        {running ? "running…" : "Run end-to-end demo"}
      </button>

      {error && (
        <pre style={{ color: "crimson", whiteSpace: "pre-wrap", marginTop: "1rem" }}>{error}</pre>
      )}

      {log.length > 0 && (
        <ol style={{ color: "#444", fontSize: "0.9rem", marginTop: "1.25rem" }}>
          {log.map((line, i) => (
            <li key={`${i}-${line}`}>{line}</li>
          ))}
        </ol>
      )}

      {result && (
        <section style={{ marginTop: "1.5rem" }}>
          <h2>Decrypted at each endpoint</h2>
          <p>
            Alice ({result.aliceFingerprint}…) read:{" "}
            <strong data-testid="alice-read">“{result.aliceDecrypted}”</strong>
          </p>
          <p>
            Bob ({result.bobFingerprint}…) read:{" "}
            <strong data-testid="bob-read">“{result.bobDecrypted}”</strong>
          </p>

          <h2>What the relay stored (it is blind)</h2>
          <p style={{ color: "#555", fontSize: "0.9rem" }}>
            The relay holds only an opaque queue id, an envelope id, and ciphertext — no identity,
            no sender, nothing linking the two queues.
          </p>
          <table style={{ ...mono, fontSize: "0.8rem", borderCollapse: "collapse", width: "100%" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid #ccc" }}>
                <th>queue…</th>
                <th>envelope id</th>
                <th>payload (sealed)</th>
                <th>bytes</th>
              </tr>
            </thead>
            <tbody>
              {result.relayView.map((e) => (
                <tr key={e.envelopeId} style={{ borderBottom: "1px solid #eee" }}>
                  <td>{e.queue}…</td>
                  <td>{e.envelopeId.slice(0, 8)}…</td>
                  <td>{e.payloadPreview}</td>
                  <td>{e.bytes}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h2>Node CA pin (PQ-mTLS)</h2>
          <p style={{ color: "#555", fontSize: "0.9rem" }}>
            {result.caFingerprint ? (
              <>
                The invite pins the queue node's CA{" "}
                <span style={mono} data-testid="ca-fingerprint">
                  {result.caFingerprint.slice(0, 32)}…
                </span>{" "}
                — {result.caPinVerified ? "verified against the node" : "advertised but unverified"}.
                Native node↔node clients enforce this pin at the TLS layer (X25519MLKEM768).
              </>
            ) : (
              <>
                The dev node serves plain HTTP (loopback), so the invite carries no CA pin. With{" "}
                <code>[pki] enabled</code> the node is its own CA and the invite pins its fingerprint.
              </>
            )}
          </p>

          <h2>Invite</h2>
          <p style={{ ...mono, fontSize: "0.75rem", wordBreak: "break-all", color: "#666" }}>
            {result.inviteUri.slice(0, 120)}…
          </p>
        </section>
      )}
    </main>
  );
}
