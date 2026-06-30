//! The Double Ratchet (`doc/design.md` §5.3): per-message forward secrecy from symmetric
//! chains, plus post-compromise "healing" from a Diffie-Hellman step each time the
//! conversation changes direction.
//!
//! Initialisation hands off from [`crate::pqxdh`]: the initiator seeds the root with the
//! shared key and the responder's signed prekey (its first ratchet public); the responder
//! seeds the root and keeps its signed-prekey secret as its first ratchet key. Out-of-order
//! and dropped messages are tolerated via a bounded store of skipped message keys.
//!
//! The message header reserves room for the future PQ-rekey layer through the wire codec's
//! reserved tags — adding ML-KEM rekeys later is additive, not a wire break (§5.3).

mod chain;
mod header;

use std::collections::HashMap;

use chain::{ChainKey, RootKey, kdf_ck, kdf_rk, message_keys};
pub use header::Header;
use header::read_u32;

use crate::aead;
use crate::error::CryptoError;
use crate::kem::{X25519PublicKey, X25519SecretKey};
use crate::wire::{Frame, TAG_CIPHERTEXT, TAG_RATCHET_DH, TAG_RATCHET_N, TAG_RATCHET_PN};

/// Maximum messages that may be skipped within a single receiving chain before a gap is
/// treated as abuse rather than ordinary loss/reordering.
pub const MAX_SKIP: u32 = 1000;
/// Hard cap on retained skipped message keys across all chains (bounds memory under attack).
const MAX_STORED_SKIPPED: usize = 2000;

/// One end of a Double Ratchet session. Holds secret chain state; not `Clone`.
pub struct RatchetState {
    dhs: X25519SecretKey,
    dhs_pub: X25519PublicKey,
    dhr: Option<X25519PublicKey>,
    rk: RootKey,
    cks: Option<ChainKey>,
    ckr: Option<ChainKey>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: HashMap<([u8; 32], u32), [u8; 32]>,
}

impl RatchetState {
    /// Initialise the **initiator** (the party who sent the handshake): seed with the shared
    /// `root` and the responder's first ratchet public key (its signed prekey). The initiator
    /// can send immediately.
    #[must_use]
    pub fn initiator(root: [u8; 32], remote_ratchet_key: X25519PublicKey) -> Self {
        let dhs = X25519SecretKey::generate();
        let dhs_pub = dhs.public_key();
        let (rk, cks) = kdf_rk(&root, &dhs.diffie_hellman(&remote_ratchet_key));
        Self {
            dhs,
            dhs_pub,
            dhr: Some(remote_ratchet_key),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// Initialise the **responder**: seed with the shared `root` and keep the signed-prekey
    /// secret as the first ratchet key. The responder must *receive* a message before it can
    /// send (the first receive establishes its sending chain).
    #[must_use]
    pub fn responder(root: [u8; 32], ratchet_key: X25519SecretKey) -> Self {
        let dhs_pub = ratchet_key.public_key();
        Self {
            dhs: ratchet_key,
            dhs_pub,
            dhr: None,
            rk: root,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: HashMap::new(),
        }
    }

    /// Encrypt `plaintext`, advancing the sending chain. Returns a self-describing wire
    /// message (header + ciphertext). Fails if no sending chain exists yet (a responder that
    /// has not received the first message).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let ck = self
            .cks
            .ok_or(CryptoError::Ratchet("no sending chain yet"))?;
        let (next_ck, mk) = kdf_ck(&ck);
        self.cks = Some(next_ck);

        let header = Header {
            dh: self.dhs_pub,
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let aad = header.to_aad();
        let (key, nonce) = message_keys(&mk);
        let ciphertext = aead::seal(&key, &nonce, &aad, plaintext)?;

        Ok(Frame::new()
            .with_field(TAG_RATCHET_DH, header.dh.to_bytes().to_vec())
            .with_field(TAG_RATCHET_PN, header.pn.to_be_bytes().to_vec())
            .with_field(TAG_RATCHET_N, header.n.to_be_bytes().to_vec())
            .with_field(TAG_CIPHERTEXT, ciphertext)
            .encode())
    }

    /// Decrypt a wire message, performing a DH ratchet step and/or skipping keys as the header
    /// requires. Tolerates out-of-order and dropped messages within [`MAX_SKIP`].
    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let frame = Frame::decode(message)?;
        let header = Header {
            dh: X25519PublicKey::from_slice(frame.require(TAG_RATCHET_DH)?)?,
            pn: read_u32(frame.require(TAG_RATCHET_PN)?)?,
            n: read_u32(frame.require(TAG_RATCHET_N)?)?,
        };
        let ciphertext = frame.require(TAG_CIPHERTEXT)?;
        let aad = header.to_aad();

        // 1. A previously skipped message key for exactly this (ratchet key, index)?
        if let Some(mk) = self.skipped.remove(&(header.dh.to_bytes(), header.n)) {
            return open(&mk, &aad, ciphertext);
        }

        // 2. A new ratchet public key means the sender turned the DH ratchet: bank the rest of
        //    the current receiving chain, then step.
        if self.dhr.map(|r| r.to_bytes()) != Some(header.dh.to_bytes()) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(&header);
        }

        // 3. Skip forward within the current receiving chain to this message's index.
        self.skip_message_keys(header.n)?;

        // 4. Derive this message's key and open.
        let ck = self.ckr.ok_or(CryptoError::Ratchet("no receiving chain"))?;
        let (next_ck, mk) = kdf_ck(&ck);
        self.ckr = Some(next_ck);
        self.nr += 1;
        open(&mk, &aad, ciphertext)
    }

    /// Advance the current receiving chain up to `until`, stashing each skipped message key so
    /// a late/out-of-order message can still be opened.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), CryptoError> {
        let Some(dhr) = self.dhr.map(|r| r.to_bytes()) else {
            return Ok(()); // no receiving chain established yet
        };
        if self.ckr.is_none() {
            return Ok(());
        }
        if until > self.nr.saturating_add(MAX_SKIP) {
            return Err(CryptoError::Ratchet("too many skipped messages"));
        }
        while self.nr < until {
            let ck = self.ckr.expect("receiving chain present in loop");
            let (next_ck, mk) = kdf_ck(&ck);
            self.ckr = Some(next_ck);
            if self.skipped.len() >= MAX_STORED_SKIPPED {
                return Err(CryptoError::Ratchet("skipped-key store full"));
            }
            self.skipped.insert((dhr, self.nr), mk);
            self.nr += 1;
        }
        Ok(())
    }

    /// Turn the DH ratchet: adopt the peer's new ratchet key, derive a fresh receiving chain,
    /// generate our next ratchet key, and derive a fresh sending chain.
    fn dh_ratchet(&mut self, header: &Header) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header.dh);

        let (rk, ckr) = kdf_rk(&self.rk, &self.dhs.diffie_hellman(&header.dh));
        self.rk = rk;
        self.ckr = Some(ckr);

        self.dhs = X25519SecretKey::generate();
        self.dhs_pub = self.dhs.public_key();
        let (rk, cks) = kdf_rk(&self.rk, &self.dhs.diffie_hellman(&header.dh));
        self.rk = rk;
        self.cks = Some(cks);
    }
}

/// Derive the AEAD key/nonce from a message key and open the ciphertext.
fn open(mk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let (key, nonce) = message_keys(mk);
    aead::open(&key, &nonce, aad, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKeyPair;
    use crate::pqxdh::{InitialMessage, initiate, respond};
    use crate::prekey::PrekeyBundle;

    /// Run a full handshake and return the two ratchet ends (Alice=initiator, Bob=responder).
    fn session() -> (RatchetState, RatchetState) {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (bob_secrets, bob_bundle) = PrekeyBundle::generate(&bob, true);
        let (msg, root_a) = initiate(&alice, &bob_bundle);
        let msg = InitialMessage::decode(&msg.encode()).unwrap();
        let root_b = respond(&bob_bundle, &bob_secrets, &msg).unwrap();
        assert_eq!(root_a, root_b);

        let alice_r = RatchetState::initiator(root_a, bob_bundle.signed_prekey);
        let bob_r = RatchetState::responder(root_b, bob_secrets.signed_prekey);
        (alice_r, bob_r)
    }

    #[test]
    fn full_handshake_then_bidirectional_chat() {
        let (mut alice, mut bob) = session();
        // Alice must speak first (Bob has no sending chain yet).
        assert!(bob.encrypt(b"premature").is_err());

        let m1 = alice.encrypt(b"hello bob").unwrap();
        assert_eq!(bob.decrypt(&m1).unwrap(), b"hello bob");
        let r1 = bob.encrypt(b"hi alice").unwrap();
        assert_eq!(alice.decrypt(&r1).unwrap(), b"hi alice");

        // Several turns, exercising repeated DH ratchet steps.
        for i in 0..5u8 {
            let a = alice.encrypt(&[i; 4]).unwrap();
            assert_eq!(bob.decrypt(&a).unwrap(), &[i; 4]);
            let b = bob.encrypt(&[i + 100; 4]).unwrap();
            assert_eq!(alice.decrypt(&b).unwrap(), &[i + 100; 4]);
        }
    }

    #[test]
    fn out_of_order_within_a_chain() {
        let (mut alice, mut bob) = session();
        let m1 = alice.encrypt(b"one").unwrap();
        let m2 = alice.encrypt(b"two").unwrap();
        let m3 = alice.encrypt(b"three").unwrap();
        // Bob receives 1, 3, then the delayed 2.
        assert_eq!(bob.decrypt(&m1).unwrap(), b"one");
        assert_eq!(bob.decrypt(&m3).unwrap(), b"three");
        assert_eq!(bob.decrypt(&m2).unwrap(), b"two");
    }

    #[test]
    fn dropped_message_does_not_block_later_ones() {
        let (mut alice, mut bob) = session();
        let _m1 = alice.encrypt(b"lost").unwrap();
        let m2 = alice.encrypt(b"arrives").unwrap();
        // m1 never delivered; m2 still opens (its skipped key is banked).
        assert_eq!(bob.decrypt(&m2).unwrap(), b"arrives");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut alice, mut bob) = session();
        let mut m = alice.encrypt(b"secret").unwrap();
        let last = m.len() - 1;
        m[last] ^= 0x01;
        assert_eq!(bob.decrypt(&m), Err(CryptoError::Aead));
    }

    #[test]
    fn replay_is_rejected() {
        let (mut alice, mut bob) = session();
        let m = alice.encrypt(b"once").unwrap();
        assert_eq!(bob.decrypt(&m).unwrap(), b"once");
        // The message key was consumed; replay finds neither a skipped key nor the live chain.
        assert!(bob.decrypt(&m).is_err());
    }

    /// A tiny deterministic shuffle so proptest controls the delivery permutation without an
    /// extra rng-crate dependency.
    fn shuffle(order: &mut [usize], mut seed: u64) {
        for i in (1..order.len()).rev() {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = (seed >> 33) as usize % (i + 1);
            order.swap(i, j);
        }
    }

    // proptest does not build for wasm (its wait-timeout dep); run these on native only.
    #[cfg(not(target_arch = "wasm32"))]
    proptest::proptest! {
        // Out-of-order + dropped delivery within one direction: Alice sends many messages from
        // a single chain; Bob receives a permuted subset and every delivered message must still
        // open to its plaintext (skipped keys are banked, drops don't block later messages).
        #[test]
        fn permuted_and_dropped_delivery(seed in proptest::prelude::any::<u64>(), n in 1usize..40, drops in proptest::prelude::any::<u64>()) {
            let (mut alice, mut bob) = session();
            let plaintexts: Vec<Vec<u8>> = (0..n).map(|i| format!("msg-{i}").into_bytes()).collect();
            let ciphertexts: Vec<Vec<u8>> = plaintexts.iter().map(|m| alice.encrypt(m).unwrap()).collect();

            let mut order: Vec<usize> = (0..n).collect();
            shuffle(&mut order, seed);
            for &i in &order {
                // Drop ~half the messages (those never delivered just stay banked as skipped keys).
                if (drops >> (i % 64)) & 1 == 1 {
                    continue;
                }
                proptest::prop_assert_eq!(bob.decrypt(&ciphertexts[i]).unwrap(), plaintexts[i].clone());
            }
        }

        // Long in-order bidirectional conversation: many DH ratchet steps, every message opens.
        #[test]
        fn bidirectional_in_order(rounds in 1usize..60) {
            let (mut alice, mut bob) = session();
            for i in 0..rounds {
                let a_msg = format!("a{i}").into_bytes();
                let a = alice.encrypt(&a_msg).unwrap();
                proptest::prop_assert_eq!(bob.decrypt(&a).unwrap(), a_msg);
                let b_msg = format!("b{i}").into_bytes();
                let b = bob.encrypt(&b_msg).unwrap();
                proptest::prop_assert_eq!(alice.decrypt(&b).unwrap(), b_msg);
            }
        }
    }
}
