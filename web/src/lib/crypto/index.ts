// Typed facade over the wasm-pack output of `buh-crypto`. The `pkg/` directory is generated
// (gitignored) by `npm run wasm`; everything in the app imports the crypto core through here,
// never from `pkg/` directly, so the real Phase-4 API (generateIdentity, createInvite, …) can
// grow behind this single seam.
//
// Because the package is built `--target bundler`, importing these bindings instantiates the
// wasm module via a top-level await — no explicit init() call is needed.
export {
  echo,
  version,
  wire_self_test as wireSelfTest,
  aead_self_test as aeadSelfTest,
  identity_self_test as identitySelfTest,
} from "./pkg/buh_crypto";
