//! End-to-end session flow over the *serialised* state blobs — exactly the handoff the WASM
//! facade and the web demo perform, but driven from the native library API so it runs in the
//! normal test suite. Proves that persisting and reloading every piece of state (identity
//! seed, prekey secrets, ratchet session) across each step still yields a working,
//! bidirectional, ratcheted conversation.

use buh_crypto::identity::IdentityKeyPair;
use buh_crypto::invite::{CA_FINGERPRINT_LEN, INVITE_NONCE_LEN, Invite, QueueDescriptor};
use buh_crypto::pqxdh::{InitialMessage, initiate, respond};
use buh_crypto::prekey::{PrekeyBundle, PrekeySecrets};
use buh_crypto::ratchet::RatchetState;

/// Reload a value through its byte blob, mimicking a KeyStore read between calls.
fn reload_session(blob: &[u8]) -> RatchetState {
    RatchetState::from_bytes(blob).expect("session blob round-trips")
}

#[test]
fn invite_to_ratcheted_conversation_over_blobs() {
    // --- Alice (inviter / responder) sets herself up and publishes an invite. ---
    let alice_identity_seed = IdentityKeyPair::generate().to_seed();
    let alice_id = IdentityKeyPair::from_seed(&alice_identity_seed);
    let (alice_secrets, alice_bundle) = PrekeyBundle::generate(&alice_id, true);
    let alice_secrets_blob = alice_secrets.to_bytes();
    let alice_bundle_blob = alice_bundle.encode();

    let queue = QueueDescriptor {
        queue_id: [0x41; 32],
        relay_url: "https://relay.test:8443".to_owned(),
        ca_fingerprint: [0x42; CA_FINGERPRINT_LEN],
    };
    let invite_uri = Invite::create(
        &alice_id,
        queue.clone(),
        PrekeyBundle::decode(&alice_bundle_blob).unwrap(),
        [0x43; INVITE_NONCE_LEN],
        4_000_000_000_000,
    )
    .to_uri();

    // --- Bob (invitee / initiator) parses the invite and opens a session. ---
    let parsed = Invite::parse(&invite_uri).expect("invite verifies");
    assert_eq!(parsed.queue.queue_id, [0x41; 32]); // where Bob will deliver
    let bob_identity_seed = IdentityKeyPair::generate().to_seed();
    let bob_id = IdentityKeyPair::from_seed(&bob_identity_seed);

    let (handshake, root_bob) = initiate(&bob_id, &parsed.bundle);
    let initial_message_bytes = handshake.encode();
    let mut bob_session = RatchetState::initiator(root_bob, parsed.bundle.signed_prekey);
    let hello = bob_session.encrypt(b"hello alice").unwrap();
    let bob_session_blob = bob_session.to_bytes(); // persisted

    // Over the wire Bob delivers (initial_message_bytes, hello) to Alice's queue.

    // --- Alice accepts from her stored secrets + bundle, and decrypts. ---
    let alice_secrets = PrekeySecrets::from_bytes(&alice_secrets_blob).unwrap();
    let alice_bundle = PrekeyBundle::decode(&alice_bundle_blob).unwrap();
    let message = InitialMessage::decode(&initial_message_bytes).unwrap();
    let root_alice = respond(&alice_bundle, &alice_secrets, &message).unwrap();
    let mut alice_session = RatchetState::responder(root_alice, alice_secrets.signed_prekey);
    assert_eq!(alice_session.decrypt(&hello).unwrap(), b"hello alice");
    let alice_session_blob = alice_session.to_bytes(); // persisted

    // --- Both sides reload from persisted blobs and continue a few turns. ---
    let mut alice_session = reload_session(&alice_session_blob);
    let mut bob_session = reload_session(&bob_session_blob);

    let reply = alice_session.encrypt(b"hi bob").unwrap();
    assert_eq!(bob_session.decrypt(&reply).unwrap(), b"hi bob");

    for i in 0..3u8 {
        // Persist/reload on every hop, as the KeyStore would, threading the advancing state.
        bob_session = reload_session(&bob_session.to_bytes());
        let m = bob_session.encrypt(&[i; 3]).unwrap();
        alice_session = reload_session(&alice_session.to_bytes());
        assert_eq!(alice_session.decrypt(&m).unwrap(), &[i; 3]);
        let r = alice_session.encrypt(&[i + 50; 3]).unwrap();
        assert_eq!(bob_session.decrypt(&r).unwrap(), &[i + 50; 3]);
    }
}
