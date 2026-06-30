# buh web client

Vite + React + SWC + TypeScript client. The cryptography is **not** in TypeScript: it is the
`buh-crypto` Rust crate compiled to WebAssembly (`wasm-pack`), so the web client and any future
Tauri/Rust client share one audited implementation and one wire codec
(`doc/design.md` §12).

## Build & run

```sh
npm install
npm run wasm     # wasm-pack build buh-crypto → src/lib/crypto/pkg/ (gitignored)
npm run dev      # Vite dev server
npm run build    # tsc -b && vite build → dist/
```

`npm run wasm` must be run before the first `dev`/`build` (the generated `src/lib/crypto/pkg/`
is gitignored). It is wired with `vite-plugin-wasm` + `vite-plugin-top-level-await` because the
crate is built `--target bundler`.

## Crypto boundary check

The current app is the Phase-0 boundary proof: on load it round-trips a `Uint8Array` through
`buh-crypto::echo` and runs the wire / XChaCha20-Poly1305 / ML-DSA-65 KATs **in the browser**,
confirming the Rust↔WASM marshalling and the `wasm_js` getrandom backend behave before any real
session code depends on them. The real envelope-oriented facade (`generateIdentity`,
`createInvite`, `encryptMessage`, …) and the `IndexedDbKeyStore` land in Phase 4.

All crypto is imported through `src/lib/crypto/` — never from `pkg/` directly.
