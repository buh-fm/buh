//! The crypto KATs, run in a real wasm runtime via `wasm-bindgen-test`.
//!
//! This is the other half of the Phase-2 gate: every primitive must pass *both* native (the
//! `#[test]` suites in each module) and wasm. Running here catches a `wasm_js`-getrandom or
//! encoding divergence that a native-only suite would miss.
//!
//! Run with: `wasm-pack test --node` (or `--headless --firefox`) from `crates/buh-crypto`.
#![cfg(target_arch = "wasm32")]

use buh_crypto::aead;
use buh_crypto::identity::IdentityKeyPair;
use buh_crypto::pqxdh::{InitialMessage, initiate, respond};
use buh_crypto::prekey::PrekeyBundle;
use buh_crypto::ratchet::RatchetState;
use buh_crypto::wire::{FLAG_HANDSHAKE, Frame, TAG_IDENTITY_PUB, TAG_PQ_EPOCH, TAG_SIGNATURE};
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn wire_roundtrip_and_pq_gate() {
    let frame = Frame::new()
        .with_flags(FLAG_HANDSHAKE)
        .with_field(TAG_IDENTITY_PUB, vec![1, 2, 3])
        .with_field(TAG_SIGNATURE, vec![9; 8]);
    let back = Frame::decode(&frame.encode()).unwrap();
    assert_eq!(back, frame);
    assert!(back.reject_reserved_pq().is_ok());
    // Messaging skips a reserved tag; the handshake gate rejects it.
    let pq = Frame::decode(&Frame::new().with_field(TAG_PQ_EPOCH, vec![1]).encode()).unwrap();
    assert!(pq.reject_reserved_pq().is_err());
}

#[wasm_bindgen_test]
fn aead_xchacha_kat() {
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
    let expected: [u8; 130] = [
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
    let sealed = aead::seal(&key, &nonce, &aad, plaintext).unwrap();
    assert_eq!(sealed, expected);
    assert_eq!(aead::open(&key, &nonce, &aad, &sealed).unwrap(), plaintext);
}

#[wasm_bindgen_test]
fn identity_keygen_sign_verify() {
    // Exercises ML-DSA-65 keygen + hedged signing over the wasm_js getrandom backend.
    let id = IdentityKeyPair::generate();
    let pk = id.public_key();
    let msg = b"buh wasm boundary";
    let sig = id.sign(msg);
    assert!(pk.verify(msg, &sig).is_ok());
    assert!(pk.verify(b"tampered", &sig).is_err());
}

#[wasm_bindgen_test]
fn identity_deterministic_matches_native() {
    // Same fixed-seed digest assertion as the native KAT — proves encoding parity wasm↔native.
    use sha2::{Digest, Sha256};
    let id = IdentityKeyPair::from_seed(&[0u8; 32]);
    let pk_digest = hex::encode(Sha256::digest(id.public_key().to_bytes()));
    let sig_digest = hex::encode(Sha256::digest(
        id.sign_deterministic(b"buh kat v1").to_bytes(),
    ));
    assert_eq!(
        pk_digest,
        "085ba380ff386dd52e42349c6eb88489d6058ea541a4e3fb0dce9a3fd1f7a911"
    );
    assert_eq!(
        sig_digest,
        "fa1505282148194ecd8d8608eddf3a21b3645d20da99d39e44a904b4ec32d3cc"
    );
}

#[wasm_bindgen_test]
fn full_handshake_and_ratchet_in_wasm() {
    // The entire client path — ML-KEM + X25519 hybrid PQXDH and the Double Ratchet — running
    // in the browser over the wasm_js getrandom backend, the same code the web client loads.
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let (bob_secrets, bob_bundle) = PrekeyBundle::generate(&bob, true);

    let (msg, root_a) = initiate(&alice, &bob_bundle);
    let msg = InitialMessage::decode(&msg.encode()).unwrap();
    let root_b = respond(&bob_bundle, &bob_secrets, &msg).unwrap();
    assert_eq!(root_a, root_b);

    let mut alice_r = RatchetState::initiator(root_a, bob_bundle.signed_prekey);
    let mut bob_r = RatchetState::responder(root_b, bob_secrets.signed_prekey);

    let c1 = alice_r.encrypt(b"hello from wasm").unwrap();
    assert_eq!(bob_r.decrypt(&c1).unwrap(), b"hello from wasm");
    let c2 = bob_r.encrypt(b"hi back").unwrap();
    assert_eq!(alice_r.decrypt(&c2).unwrap(), b"hi back");
}
