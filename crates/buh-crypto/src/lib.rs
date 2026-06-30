//! buh client cryptography core.
//!
//! This is the smart endpoint's crypto: post-quantum identity (ML-DSA), the PQXDH hybrid
//! handshake (X25519 + ML-KEM-768), the Double Ratchet, per-file media sealing
//! (XChaCha20-Poly1305 content keys, [`media`]), the one-time signed invite, and the versioned
//! wire codec. It compiles to WASM via
//! `wasm-pack` for the Vite/React web client and is reusable by a future Tauri/Rust client.
//!
//! The node never links this crate — a relay treats envelopes as opaque bytes
//! (`doc/design.md` §3.1). Implementation lands in Phases 2–4; this is the scaffold.

// The native core is unsafe-free. The `wasm` feature relaxes this only because wasm-bindgen's
// generated FFI glue (src/ffi.rs) contains `unsafe`; the cryptographic code never does.
#![cfg_attr(not(feature = "wasm"), forbid(unsafe_code))]
#![warn(missing_docs)]

pub mod aead;
pub mod error;
pub mod identity;
pub mod invite;
pub mod kem;
pub mod media;
pub mod pqxdh;
pub mod prekey;
pub mod ratchet;
pub mod wire;

#[cfg(feature = "wasm")]
pub mod ffi;

pub use error::CryptoError;

/// Crate version string, exposed so the web bundle can assert it loaded the expected build.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Round-trip a byte buffer unchanged. Phase-0 smoke check that the Rust↔WASM boundary
/// marshals `Uint8Array` correctly before any real crypto is wired in; replaced by the real
/// API surface in Phase 4.
#[must_use]
pub fn echo(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_roundtrips() {
        assert_eq!(echo(b"buh"), b"buh");
    }
}
