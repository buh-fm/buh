//! ML-DSA-65 identity — in buh, *the user is their key* (`doc/design.md` §4). There is no
//! account, username, or server-side record; an identity is an ML-DSA-65 (FIPS 204) keypair,
//! and everything else (prekeys, invites, the handshake transcript) is signed by it.
//!
//! Signing defaults to the **hedged / randomized** variant (the FIPS 204 default): fresh
//! per-signature randomness is mixed in, hardening against fault and bad-RNG attacks.
//! [`IdentityKeyPair::sign_deterministic`] exposes the deterministic variant for reproducible
//! test vectors; both produce signatures verifiable by the same [`IdentityPublicKey::verify`].

use ml_dsa::common::getrandom::SysRng;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair, MlDsa65, Seed, Signature, SigningKey,
    VerifyingKey,
};

use crate::error::CryptoError;

/// Length of an ML-DSA seed (private key) in bytes.
pub const SEED_LEN: usize = 32;
/// Length of an encoded ML-DSA-65 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 1952;
/// Length of an encoded ML-DSA-65 signature in bytes.
pub const SIGNATURE_LEN: usize = 3309;

/// A buh identity: an ML-DSA-65 keypair. Holds secret material; never serialise it except as
/// its 32-byte seed via [`IdentityKeyPair::to_seed`].
pub struct IdentityKeyPair {
    signing_key: SigningKey<MlDsa65>,
}

impl IdentityKeyPair {
    /// Generate a fresh identity from the system RNG.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(),
        }
    }

    /// Deterministically derive an identity from a 32-byte seed. The seed *is* the private
    /// key; guard it like one. Round-trips with [`Self::to_seed`].
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let seed = Seed::from(*seed);
        Self {
            signing_key: SigningKey::from_seed(&seed),
        }
    }

    /// The 32-byte seed this identity derives from — the only safe serialisation of the
    /// private key.
    #[must_use]
    pub fn to_seed(&self) -> [u8; SEED_LEN] {
        let seed = self.signing_key.to_seed();
        let mut out = [0u8; SEED_LEN];
        out.copy_from_slice(&seed);
        out
    }

    /// This identity's public key.
    #[must_use]
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign `msg` with the hedged (randomized) variant — the production path.
    ///
    /// # Panics
    /// Panics only if the platform RNG is unavailable, which is unrecoverable.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> IdentitySignature {
        let sig = self
            .signing_key
            .expanded_key()
            .sign_randomized(msg, &[], &mut SysRng)
            .expect("hedged ML-DSA signing");
        IdentitySignature(sig)
    }

    /// Sign `msg` with the deterministic variant. Same key, reproducible output — used for
    /// known-answer vectors.
    #[must_use]
    pub fn sign_deterministic(&self, msg: &[u8]) -> IdentitySignature {
        let sig = self
            .signing_key
            .expanded_key()
            .sign_deterministic(msg, &[])
            .expect("deterministic ML-DSA signing");
        IdentitySignature(sig)
    }
}

/// An identity public key: who a peer claims to be, and the verifier for everything they sign.
#[derive(Clone)]
pub struct IdentityPublicKey {
    verifying_key: VerifyingKey<MlDsa65>,
}

impl IdentityPublicKey {
    /// The fixed-size on-wire encoding (1952 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.verifying_key.encode().to_vec()
    }

    /// Parse from the on-wire encoding. Fails on the wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes)
            .map_err(|_| CryptoError::malformed("identity public key"))?;
        Ok(Self {
            verifying_key: VerifyingKey::decode(&encoded),
        })
    }

    /// Verify `sig` over `msg`. Returns [`CryptoError::BadSignature`] on any failure.
    pub fn verify(&self, msg: &[u8], sig: &IdentitySignature) -> Result<(), CryptoError> {
        if self.verifying_key.verify_with_context(msg, &[], &sig.0) {
            Ok(())
        } else {
            Err(CryptoError::BadSignature)
        }
    }
}

/// An ML-DSA-65 signature.
#[derive(Clone)]
pub struct IdentitySignature(Signature<MlDsa65>);

impl IdentitySignature {
    /// The fixed-size on-wire encoding (3309 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }

    /// Parse from the on-wire encoding. Fails on the wrong length or a structurally invalid
    /// signature.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let encoded = EncodedSignature::<MlDsa65>::try_from(bytes)
            .map_err(|_| CryptoError::malformed("signature"))?;
        let sig = Signature::decode(&encoded).ok_or(CryptoError::malformed("signature"))?;
        Ok(Self(sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn sign_verify_roundtrip_hedged() {
        let id = IdentityKeyPair::generate();
        let pk = id.public_key();
        let msg = b"the user is their key";
        let sig = id.sign(msg);
        assert!(pk.verify(msg, &sig).is_ok());
        // Wrong message rejected.
        assert_eq!(pk.verify(b"tampered", &sig), Err(CryptoError::BadSignature));
        // Wrong key rejected.
        let other = IdentityKeyPair::generate().public_key();
        assert_eq!(other.verify(msg, &sig), Err(CryptoError::BadSignature));
    }

    #[test]
    fn seed_roundtrip_is_deterministic() {
        let seed = [42u8; SEED_LEN];
        let a = IdentityKeyPair::from_seed(&seed);
        let b = IdentityKeyPair::from_seed(&seed);
        assert_eq!(a.to_seed(), seed);
        // Same seed → same public key.
        assert_eq!(a.public_key().to_bytes(), b.public_key().to_bytes());
    }

    #[test]
    fn encoding_roundtrips_and_lengths() {
        let id = IdentityKeyPair::from_seed(&[7u8; SEED_LEN]);
        let pk_bytes = id.public_key().to_bytes();
        assert_eq!(pk_bytes.len(), PUBLIC_KEY_LEN);
        let pk = IdentityPublicKey::from_bytes(&pk_bytes).unwrap();

        let sig = id.sign_deterministic(b"hello");
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_bytes.len(), SIGNATURE_LEN);
        let sig = IdentitySignature::from_bytes(&sig_bytes).unwrap();
        assert!(pk.verify(b"hello", &sig).is_ok());

        assert!(IdentityPublicKey::from_bytes(&pk_bytes[..10]).is_err());
        assert!(IdentitySignature::from_bytes(b"short").is_err());
    }

    // Regression KAT: a fixed seed must always produce the same public key, and the
    // deterministic signing variant the same signature, byte-for-byte — native and wasm. The
    // upstream `ml-dsa` crate carries the NIST ACVP vectors; this pins our API/encoding to a
    // stable answer and catches any getrandom/wasm divergence. Digests keep the anchor compact.
    #[test]
    fn deterministic_kat_digests() {
        let id = IdentityKeyPair::from_seed(&[0u8; SEED_LEN]);
        let pk_digest = sha256_hex(&id.public_key().to_bytes());
        let sig_digest = sha256_hex(&id.sign_deterministic(b"buh kat v1").to_bytes());
        assert_eq!(pk_digest, PK_DIGEST_SEED0, "public key for seed=0 changed");
        assert_eq!(
            sig_digest, SIG_DIGEST_SEED0,
            "deterministic signature changed"
        );
    }

    const PK_DIGEST_SEED0: &str =
        "085ba380ff386dd52e42349c6eb88489d6058ea541a4e3fb0dce9a3fd1f7a911";
    const SIG_DIGEST_SEED0: &str =
        "fa1505282148194ecd8d8608eddf3a21b3645d20da99d39e44a904b4ec32d3cc";
}
