//! Hybrid key agreement: classical **X25519** alongside post-quantum **ML-KEM-768** (FIPS
//! 203). The handshake (`pqxdh`) mixes a secret from *each* so the session stays confidential
//! unless an attacker breaks **both** — the harvest-now-decrypt-later defence of
//! `doc/design.md` §5.2.
//!
//! Two independent primitives live here; combining them into a root key is `pqxdh`'s job.
//! Randomness comes from the system RNG (getrandom; `wasm_js` in the browser).

use ml_kem::Kem;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Key, MlKem768};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

/// Copy a 32-byte shared-secret array out of an `ml-kem` `Array`.
fn shared32(arr: &[u8]) -> [u8; SHARED_SECRET_LEN] {
    let mut out = [0u8; SHARED_SECRET_LEN];
    out.copy_from_slice(arr);
    out
}

use crate::error::CryptoError;

/// Length of an X25519 public key / DH output (bytes).
pub const X25519_LEN: usize = 32;
/// Length of a shared secret produced by either primitive (bytes).
pub const SHARED_SECRET_LEN: usize = 32;
/// Length of an encoded ML-KEM-768 encapsulation (public) key (bytes).
pub const MLKEM_ENCAPS_KEY_LEN: usize = 1184;
/// Length of an ML-KEM-768 ciphertext (bytes).
pub const MLKEM_CIPHERTEXT_LEN: usize = 1088;

// ---------- X25519 ----------

/// An X25519 secret key (a long-lived prekey secret or an ephemeral handshake key).
#[derive(Clone)]
pub struct X25519SecretKey(XSecret);

impl X25519SecretKey {
    /// Generate from system randomness.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; X25519_LEN];
        getrandom::fill(&mut bytes).expect("system RNG unavailable");
        Self(XSecret::from(bytes))
    }

    /// Reconstruct from raw bytes (clamped by X25519).
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_LEN]) -> Self {
        Self(XSecret::from(bytes))
    }

    /// The raw secret bytes — guard like a private key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X25519_LEN] {
        self.0.to_bytes()
    }

    /// The corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(XPublic::from(&self.0))
    }

    /// Diffie-Hellman with a peer public key, yielding a 32-byte shared secret.
    #[must_use]
    pub fn diffie_hellman(&self, peer: &X25519PublicKey) -> [u8; SHARED_SECRET_LEN] {
        self.0.diffie_hellman(&peer.0).to_bytes()
    }
}

/// An X25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(XPublic);

impl X25519PublicKey {
    /// The 32-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X25519_LEN] {
        self.0.to_bytes()
    }

    /// Parse from a 32-byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let arr: [u8; X25519_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError::malformed("x25519 public key"))?;
        Ok(Self(XPublic::from(arr)))
    }
}

// ---------- ML-KEM-768 ----------

/// An ML-KEM-768 decapsulation (secret) key.
pub struct MlKemSecretKey(DecapsulationKey);

/// An ML-KEM-768 encapsulation (public) key.
#[derive(Clone)]
pub struct MlKemPublicKey(EncapsulationKey);

impl MlKemSecretKey {
    /// Generate a fresh ML-KEM-768 keypair from system randomness.
    #[must_use]
    pub fn generate() -> (Self, MlKemPublicKey) {
        let (dk, ek) = MlKem768::generate_keypair();
        (Self(dk), MlKemPublicKey(ek))
    }

    /// Decapsulate a ciphertext to recover the shared secret. Fails if the ciphertext is the
    /// wrong length. ML-KEM's implicit rejection means a tampered ciphertext yields a
    /// different (but non-erroring) secret, so the handshake transcript binding is what
    /// actually authenticates.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; SHARED_SECRET_LEN], CryptoError> {
        let ct = Ciphertext::try_from(ciphertext)
            .map_err(|_| CryptoError::malformed("ml-kem ciphertext"))?;
        Ok(shared32(&self.0.decapsulate(&ct)))
    }
}

impl MlKemPublicKey {
    /// Encapsulate to this key: returns the ciphertext to send and the shared secret to keep.
    #[must_use]
    pub fn encapsulate(&self) -> (Vec<u8>, [u8; SHARED_SECRET_LEN]) {
        let (ct, shared) = self.0.encapsulate();
        (ct.to_vec(), shared32(&shared))
    }

    /// The encoded public key (1184 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Parse from the encoded form.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key = Key::<EncapsulationKey>::try_from(bytes)
            .map_err(|_| CryptoError::malformed("ml-kem public key"))?;
        EncapsulationKey::new(&key)
            .map(Self)
            .map_err(|_| CryptoError::malformed("ml-kem public key"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_dh_agrees() {
        let a = X25519SecretKey::generate();
        let b = X25519SecretKey::generate();
        let ab = a.diffie_hellman(&b.public_key());
        let ba = b.diffie_hellman(&a.public_key());
        assert_eq!(ab, ba);
        assert_ne!(ab, [0u8; 32]);
    }

    #[test]
    fn x25519_encoding_roundtrips() {
        let sk = X25519SecretKey::generate();
        let sk2 = X25519SecretKey::from_bytes(sk.to_bytes());
        assert_eq!(sk.public_key().to_bytes(), sk2.public_key().to_bytes());
        let pk = sk.public_key();
        let pk2 = X25519PublicKey::from_slice(&pk.to_bytes()).unwrap();
        assert_eq!(pk, pk2);
        assert!(X25519PublicKey::from_slice(&[0u8; 31]).is_err());
    }

    #[test]
    fn mlkem_encapsulate_decapsulate_agrees() {
        let (dk, ek) = MlKemSecretKey::generate();
        let (ct, ss_sender) = ek.encapsulate();
        assert_eq!(ct.len(), MLKEM_CIPHERTEXT_LEN);
        let ss_receiver = dk.decapsulate(&ct).unwrap();
        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn mlkem_public_key_roundtrips() {
        let (_dk, ek) = MlKemSecretKey::generate();
        let bytes = ek.to_bytes();
        assert_eq!(bytes.len(), MLKEM_ENCAPS_KEY_LEN);
        let ek2 = MlKemPublicKey::from_slice(&bytes).unwrap();
        // Encapsulate to the re-parsed key; the original secret still decapsulates it.
        let (ct, ss) = ek2.encapsulate();
        assert_eq!(_dk.decapsulate(&ct).unwrap(), ss);
        assert!(MlKemPublicKey::from_slice(&bytes[..10]).is_err());
    }

    #[test]
    fn mlkem_wrong_key_disagrees() {
        let (dk_a, _ek_a) = MlKemSecretKey::generate();
        let (_dk_b, ek_b) = MlKemSecretKey::generate();
        let (ct, ss_sender) = ek_b.encapsulate();
        // Decapsulating B's ciphertext with A's key gives a different secret (implicit reject).
        let ss_wrong = dk_a.decapsulate(&ct).unwrap();
        assert_ne!(ss_sender, ss_wrong);
    }
}
