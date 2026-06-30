import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vite";
import topLevelAwait from "vite-plugin-top-level-await";
import wasm from "vite-plugin-wasm";

// buh-crypto is a wasm-pack `--target bundler` module: it imports the `.wasm` as an ES module
// and instantiates it with a top-level await. `vite-plugin-wasm` resolves the wasm import and
// `vite-plugin-top-level-await` lets the resulting TLA work in browsers that need it.
//
// `/v1` is proxied to a locally-running `buh-api` relay so the browser talks to it same-origin
// (no CORS, no relay changes). Adjust the target if the relay binds elsewhere.
const RELAY = "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react(), wasm(), topLevelAwait()],
  server: { proxy: { "/v1": { target: RELAY, changeOrigin: true } } },
  preview: { proxy: { "/v1": { target: RELAY, changeOrigin: true } } },
});
