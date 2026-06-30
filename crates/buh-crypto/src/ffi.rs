//! The `wasm-bindgen` FFI surface, compiled only under the `wasm` feature for the web client.
//!
//! Phase 0 keeps this deliberately small: `echo` proves the `Uint8Array` boundary marshals
//! correctly, and the `*_self_test` helpers run the native KATs *inside the browser* so the
//! web app can confirm the entire crypto stack — the TLV codec, XChaCha20-Poly1305, and
//! ML-DSA-65 keygen/sign/verify over the `wasm_js` getrandom backend — behaves identically to
//! native before any real session code depends on it. The full envelope-oriented facade
//! (`generateIdentity`, `createInvite`, …) lands in Phase 4.

use wasm_bindgen::prelude::wasm_bindgen;

use crate::{aead, identity::IdentityKeyPair, wire};

/// The crate version, so the bundle can assert it loaded the expected build.
#[wasm_bindgen]
#[must_use]
pub fn version() -> String {
    crate::VERSION.to_string()
}

/// Round-trip a byte buffer unchanged — the boundary smoke check.
#[wasm_bindgen]
#[must_use]
pub fn echo(bytes: &[u8]) -> Vec<u8> {
    crate::echo(bytes)
}

/// Build, encode, and decode a TLV frame in wasm; returns true iff it round-trips and the
/// reserved-PQ handshake gate behaves.
#[wasm_bindgen]
#[must_use]
pub fn wire_self_test() -> bool {
    let frame = wire::Frame::new()
        .with_flags(wire::FLAG_HANDSHAKE)
        .with_field(wire::TAG_IDENTITY_PUB, vec![1, 2, 3])
        .with_field(wire::TAG_SIGNATURE, vec![9; 8]);
    let Ok(back) = wire::Frame::decode(&frame.encode()) else {
        return false;
    };
    back == frame && back.reject_reserved_pq().is_ok()
}

/// Run the XChaCha20-Poly1305 KAT (draft-arciszewski A.1) in wasm.
#[wasm_bindgen]
#[must_use]
pub fn aead_self_test() -> bool {
    let key = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let nonce = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    ];
    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: \
If I could offer you only one tip for the future, sunscreen would be it.";
    let Ok(sealed) = aead::seal(&key, &nonce, &aad, plaintext) else {
        return false;
    };
    aead::open(&key, &nonce, &aad, &sealed).as_deref() == Ok(plaintext.as_slice())
}

/// Generate an identity, sign, verify, and confirm a tampered message fails — exercising
/// ML-DSA-65 and the `wasm_js` getrandom backend in the browser.
#[wasm_bindgen]
#[must_use]
pub fn identity_self_test() -> bool {
    let id = IdentityKeyPair::generate();
    let pk = id.public_key();
    let msg = b"buh wasm boundary";
    let sig = id.sign(msg);
    pk.verify(msg, &sig).is_ok() && pk.verify(b"tampered", &sig).is_err()
}
