// Typed facade over the wasm-pack output of `buh-crypto`. The `pkg/` directory is generated
// (gitignored) by `npm run wasm`; everything in the app imports the crypto core through here,
// never from `pkg/` directly, so the surface stays small and swappable.
//
// Because the package is built `--target bundler`, importing these bindings instantiates the
// wasm module via a top-level await — no explicit init() call is needed.
export {
  version,
  // Phase-0 boundary self-tests (still surfaced as a diagnostics panel).
  echo,
  wire_self_test as wireSelfTest,
  aead_self_test as aeadSelfTest,
  identity_self_test as identitySelfTest,
  // Session facade.
  generate_identity as generateIdentity,
  identity_public_key as identityPublicKey,
  publishable_prekey_bundle as publishablePrekeyBundle,
  create_invite as createInvite,
  parse_invite as parseInvite,
  initiate_session as initiateSession,
  accept_session as acceptSession,
  encrypt_message as encryptMessage,
  decrypt_message as decryptMessage,
  // Media facade — per-file content-key sealing for the blob path.
  seal_media as sealMedia,
  open_media as openMedia,
  PrekeyMaterial,
  ParsedInvite,
  InitiatedSession,
  EncryptedMessage,
  DecryptedMessage,
  SealedMedia,
} from "./pkg/buh_crypto";
