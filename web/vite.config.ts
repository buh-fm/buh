import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vite";
import topLevelAwait from "vite-plugin-top-level-await";
import wasm from "vite-plugin-wasm";

// buh-crypto is a wasm-pack `--target bundler` module: it imports the `.wasm` as an ES module
// and instantiates it with a top-level await. `vite-plugin-wasm` resolves the wasm import and
// `vite-plugin-top-level-await` lets the resulting TLA work in browsers that need it.
export default defineConfig({
  plugins: [react(), wasm(), topLevelAwait()],
});
