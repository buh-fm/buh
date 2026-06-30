//! XChaCha20-Poly1305 authenticated encryption — the sealing primitive for envelopes (now)
//! and media (Phase 5).
//!
//! XChaCha20's 24-byte nonce is wide enough to pick at random per message without birthday
//! concern, which is exactly what the ratchet wants. This module is intentionally
//! *nonce-explicit*: the caller supplies the nonce, so sealing is a pure function and the KATs
//! below pin the exact ciphertext bytes. Higher layers (the ratchet) own nonce derivation;
//! [`random_nonce`] is provided for the one-off cases (media content keys) that need a fresh
//! random nonce.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

use crate::error::CryptoError;

/// AEAD key length (bytes).
pub const KEY_LEN: usize = 32;
/// XChaCha20 nonce length (bytes).
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length (bytes), appended to the ciphertext by [`seal`].
pub const TAG_LEN: usize = 16;

/// Seal `plaintext` under `key`/`nonce`, binding `aad`. Returns ciphertext‖tag.
///
/// `aad` is authenticated but not encrypted; bind the wire prelude+flags here (see
/// [`crate::wire::Frame::aad`]) so a version/capability downgrade fails authentication.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// Open `ciphertext` (ciphertext‖tag) under `key`/`nonce`, checking `aad`. Fails on any
/// mismatch without distinguishing the cause.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

/// A fresh random nonce from the system RNG (or the wasm `wasm_js` backend).
///
/// # Panics
/// Panics only if the platform RNG is unavailable, which is unrecoverable.
#[must_use]
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("system RNG unavailable");
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    // Published KAT from draft-arciszewski-xchacha-03 Appendix A.1 (also a genuine
    // interop vector). Pins our XChaCha20-Poly1305 wiring to the standard, native and wasm.
    const KEY: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const NONCE: [u8; 24] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    const AAD: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    // CIPHERTEXT‖TAG from the same vector.
    const EXPECTED: [u8; 130] = [
        0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9,
        0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39,
        0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e,
        0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
        0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45, 0xb1, 0x1b, 0x69,
        0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2,
        0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76,
        0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e, 0xc0, 0x87, 0x59, 0x24, 0xc1, 0xc7,
        0x98, 0x79, 0x47, 0xde, 0xaf, 0xd8, 0x78, 0x0a, 0xcf, 0x49,
    ];

    #[test]
    fn xchacha20poly1305_kat() {
        let sealed = seal(&KEY, &NONCE, &AAD, PLAINTEXT).unwrap();
        assert_eq!(sealed, EXPECTED);
        let opened = open(&KEY, &NONCE, &AAD, &sealed).unwrap();
        assert_eq!(opened, PLAINTEXT);
    }

    #[test]
    fn roundtrip_with_empty_and_aad() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let sealed = seal(&key, &nonce, b"prelude", b"hello buh").unwrap();
        assert_eq!(sealed.len(), b"hello buh".len() + TAG_LEN);
        assert_eq!(
            open(&key, &nonce, b"prelude", &sealed).unwrap(),
            b"hello buh"
        );
    }

    #[test]
    fn tamper_is_rejected() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let aad = b"v1";
        let mut sealed = seal(&key, &nonce, aad, b"secret").unwrap();
        // Flipped ciphertext byte.
        let mut bad_ct = sealed.clone();
        bad_ct[0] ^= 0x01;
        assert_eq!(open(&key, &nonce, aad, &bad_ct), Err(CryptoError::Aead));
        // Flipped tag byte.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(open(&key, &nonce, aad, &sealed), Err(CryptoError::Aead));
        // Wrong AAD (downgrade): same ciphertext, different authenticated context.
        let good = seal(&key, &nonce, aad, b"secret").unwrap();
        assert_eq!(open(&key, &nonce, b"v2", &good), Err(CryptoError::Aead));
        // Wrong key.
        assert_eq!(
            open(&[8u8; KEY_LEN], &nonce, aad, &good),
            Err(CryptoError::Aead)
        );
    }

    #[test]
    fn random_nonces_differ() {
        assert_ne!(random_nonce(), random_nonce());
    }
}
