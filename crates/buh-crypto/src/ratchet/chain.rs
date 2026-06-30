//! The Double Ratchet's key-derivation functions, all HKDF-SHA256.
//!
//! Hash-based symmetric chains are already quantum-safe (`doc/design.md` §5.3), so nothing
//! here changes when the PQ-rekey layer is added later — that layer slots in at the root KDF
//! via the reserved wire tags, not by altering these chains.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::aead::{KEY_LEN, NONCE_LEN};

/// 32-byte root key.
pub type RootKey = [u8; 32];
/// 32-byte chain key.
pub type ChainKey = [u8; 32];
/// 32-byte per-message key.
pub type MessageKey = [u8; 32];

const RK_INFO: &[u8] = b"buh-ratchet-rk-v1";
const CK_NEXT_INFO: &[u8] = b"buh-ratchet-ck-v1";
const MK_INFO: &[u8] = b"buh-ratchet-mk-v1";
const MSG_KEYS_INFO: &[u8] = b"buh-ratchet-msg-keys-v1";

/// Root KDF: advance the root key with a fresh DH output, producing the next root and a new
/// chain key. `rk` is the HKDF salt, the DH output the keying material.
#[must_use]
pub fn kdf_rk(rk: &RootKey, dh_out: &[u8; 32]) -> (RootKey, ChainKey) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut out = [0u8; 64];
    hk.expand(RK_INFO, &mut out).expect("64 within HKDF limit");
    let mut next_rk = [0u8; 32];
    let mut chain = [0u8; 32];
    next_rk.copy_from_slice(&out[..32]);
    chain.copy_from_slice(&out[32..]);
    (next_rk, chain)
}

/// Chain KDF: ratchet a chain key forward one step, yielding the next chain key and the
/// message key for this step. The chain key is used as the HKDF pseudo-random key directly.
#[must_use]
pub fn kdf_ck(ck: &ChainKey) -> (ChainKey, MessageKey) {
    let hk = Hkdf::<Sha256>::from_prk(ck).expect("32-byte PRK");
    let mut next = [0u8; 32];
    let mut mk = [0u8; 32];
    hk.expand(CK_NEXT_INFO, &mut next)
        .expect("32 within HKDF limit");
    hk.expand(MK_INFO, &mut mk).expect("32 within HKDF limit");
    (next, mk)
}

/// Expand a message key into the AEAD key and nonce for one message.
#[must_use]
pub fn message_keys(mk: &MessageKey) -> ([u8; KEY_LEN], [u8; NONCE_LEN]) {
    let hk = Hkdf::<Sha256>::from_prk(mk).expect("32-byte PRK");
    let mut out = [0u8; KEY_LEN + NONCE_LEN];
    hk.expand(MSG_KEYS_INFO, &mut out)
        .expect("key+nonce within HKDF limit");
    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    key.copy_from_slice(&out[..KEY_LEN]);
    nonce.copy_from_slice(&out[KEY_LEN..]);
    (key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_rk_is_deterministic_and_separates_outputs() {
        let rk = [1u8; 32];
        let dh = [2u8; 32];
        let (rk1, ck1) = kdf_rk(&rk, &dh);
        let (rk2, ck2) = kdf_rk(&rk, &dh);
        assert_eq!((rk1, ck1), (rk2, ck2));
        assert_ne!(rk1, ck1);
        assert_ne!(rk1, rk); // root actually advanced
    }

    #[test]
    fn kdf_ck_advances() {
        let ck = [9u8; 32];
        let (next, mk) = kdf_ck(&ck);
        assert_ne!(next, ck);
        assert_ne!(next, mk);
        // Deterministic.
        assert_eq!(kdf_ck(&ck), (next, mk));
    }

    #[test]
    fn message_keys_split_key_and_nonce() {
        let (k_a, n_a) = message_keys(&[7u8; 32]);
        let (k_b, n_b) = message_keys(&[8u8; 32]);
        assert_ne!(k_a, k_b);
        assert_ne!(n_a, n_b);
        assert_eq!(message_keys(&[7u8; 32]), (k_a, n_a));
    }
}
