import { useEffect, useState } from "react";
import {
  aeadSelfTest,
  echo,
  identitySelfTest,
  version,
  wireSelfTest,
} from "./lib/crypto";

interface Check {
  name: string;
  pass: boolean;
  detail: string;
}

// Proves the Rust↔WASM boundary before any real session code depends on it: a Uint8Array
// must survive the round trip unchanged, and the crypto core's own KATs (wire codec,
// XChaCha20-Poly1305, ML-DSA-65 over the wasm_js getrandom backend) must pass in the browser.
function runChecks(): Check[] {
  const input = new Uint8Array([0xb0, 0x01, 0x00, 0xff, 0x42]);
  const output = echo(input);
  const roundTripped =
    output.length === input.length && output.every((b, i) => b === input[i]);

  return [
    {
      name: "Uint8Array round-trips Rust↔WASM",
      pass: roundTripped,
      detail: `${[...input]} → ${[...output]}`,
    },
    { name: "wire TLV codec KAT", pass: wireSelfTest(), detail: "encode/decode + PQ gate" },
    { name: "XChaCha20-Poly1305 KAT", pass: aeadSelfTest(), detail: "draft-arciszewski A.1" },
    {
      name: "ML-DSA-65 keygen/sign/verify",
      pass: identitySelfTest(),
      detail: "hedged signing, wasm_js RNG",
    },
  ];
}

export default function App() {
  const [checks, setChecks] = useState<Check[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    try {
      setChecks(runChecks());
    } catch (e) {
      setError(String(e));
    }
  }, []);

  const allPass = checks?.every((c) => c.pass) ?? false;

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", maxWidth: 640, margin: "3rem auto" }}>
      <h1>buh crypto boundary</h1>
      <p>
        buh-crypto v{checks ? version() : "…"} —{" "}
        <strong style={{ color: allPass ? "green" : error ? "crimson" : "gray" }}>
          {error ? "ERROR" : allPass ? "all checks pass" : "running…"}
        </strong>
      </p>
      {error && <pre style={{ color: "crimson" }}>{error}</pre>}
      <ul style={{ listStyle: "none", padding: 0 }}>
        {checks?.map((c) => (
          <li key={c.name} data-testid="check" data-pass={c.pass} style={{ padding: "0.35rem 0" }}>
            <span style={{ color: c.pass ? "green" : "crimson" }}>{c.pass ? "✓" : "✗"}</span>{" "}
            {c.name} <small style={{ color: "#666" }}>— {c.detail}</small>
          </li>
        ))}
      </ul>
    </main>
  );
}
