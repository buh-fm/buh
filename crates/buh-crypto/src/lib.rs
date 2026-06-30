//! buh client cryptography core.
//!
//! This is the smart endpoint's crypto: post-quantum identity (ML-DSA), the PQXDH hybrid
//! handshake (X25519 + ML-KEM-768), the Double Ratchet, media sealing (XChaCha20-Poly1305),
//! the one-time signed invite, and the versioned wire codec. It compiles to WASM via
//! `wasm-pack` for the Vite/React web client and is reusable by a future Tauri/Rust client.
//!
//! The node never links this crate — a relay treats envelopes as opaque bytes
//! (`doc/design.md` §3.1). Implementation lands in Phases 2–4; this is the scaffold.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod wire;

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
