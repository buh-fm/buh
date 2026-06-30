//! Prekey bundles — the published, signed key material a contact uses to open a session
//! (`doc/design.md` §6.1). A bundle carries the owner's ML-DSA identity, a long-lived signed
//! X25519 prekey, an ML-KEM-768 encapsulation key, and an optional one-time X25519 prekey,
//! all signed by the identity key. **Verification happens on parse** ([`PrekeyBundle::decode`]):
//! a bundle whose signature does not check never becomes a value, so no caller can act on
//! unauthenticated prekeys.

use crate::error::CryptoError;
use crate::identity::{IdentityKeyPair, IdentityPublicKey, IdentitySignature};
use crate::kem::{
    MLKEM_SECRET_LEN, MlKemPublicKey, MlKemSecretKey, X25519PublicKey, X25519SecretKey,
};
use crate::wire::{
    Frame, Reader, TAG_CONTEXT, TAG_IDENTITY_PUB, TAG_MLKEM_EK, TAG_ONETIME_PREKEY,
    TAG_PREKEY_X25519, TAG_SIGNATURE,
};

/// Domain-separation label bound into every prekey signature.
const PREKEY_CONTEXT: &[u8] = b"buh-prekey-bundle-v1";

/// Version byte prefixing a serialised [`PrekeySecrets`] blob.
const SECRETS_VERSION: u8 = 1;

/// Read exactly 32 bytes from `r` into an array.
fn read_32(r: &mut Reader) -> Result<[u8; 32], CryptoError> {
    Ok(r.read_bytes(32)?
        .try_into()
        .expect("read_bytes returns exactly 32"))
}

/// The secret half of a published [`PrekeyBundle`], held by the bundle's owner so they can
/// complete the handshake as the responder. Never leaves the device.
pub struct PrekeySecrets {
    /// Secret for the long-lived signed prekey.
    pub signed_prekey: X25519SecretKey,
    /// ML-KEM-768 decapsulation key.
    pub kem_secret: MlKemSecretKey,
    /// Secret for the one-time prekey, if one was published.
    pub one_time_prekey: Option<X25519SecretKey>,
}

impl PrekeySecrets {
    /// Serialise the secret halves to a versioned blob for the device key store. Contains
    /// private keys — store sealed.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + MLKEM_SECRET_LEN + 1 + 32);
        out.push(SECRETS_VERSION);
        out.extend_from_slice(&self.signed_prekey.to_bytes());
        out.extend_from_slice(&self.kem_secret.to_bytes());
        match &self.one_time_prekey {
            Some(opk) => {
                out.push(1);
                out.extend_from_slice(&opk.to_bytes());
            }
            None => out.push(0),
        }
        out
    }

    /// Parse a blob produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut r = Reader::new(bytes);
        if r.read_u8()? != SECRETS_VERSION {
            return Err(CryptoError::malformed("prekey secrets version"));
        }
        let signed_prekey = X25519SecretKey::from_bytes(read_32(&mut r)?);
        let kem_secret = MlKemSecretKey::from_bytes(r.read_bytes(MLKEM_SECRET_LEN)?)?;
        let one_time_prekey = match r.read_u8()? {
            0 => None,
            1 => Some(X25519SecretKey::from_bytes(read_32(&mut r)?)),
            _ => return Err(CryptoError::malformed("prekey secrets opk flag")),
        };
        Ok(Self {
            signed_prekey,
            kem_secret,
            one_time_prekey,
        })
    }
}

/// A published, signed prekey bundle. Public; safe to hand out (it *is* the invite payload).
#[derive(Clone)]
pub struct PrekeyBundle {
    /// The owner's ML-DSA identity public key.
    pub identity: IdentityPublicKey,
    /// The long-lived signed X25519 prekey (the SPK).
    pub signed_prekey: X25519PublicKey,
    /// The ML-KEM-768 encapsulation key.
    pub kem_key: MlKemPublicKey,
    /// An optional one-time X25519 prekey.
    pub one_time_prekey: Option<X25519PublicKey>,
    signature: IdentitySignature,
}

/// The deterministic byte string signed by (and verified against) the identity key.
fn signing_body(
    identity: &IdentityPublicKey,
    spk: &X25519PublicKey,
    kem: &MlKemPublicKey,
    opk: Option<&X25519PublicKey>,
) -> Vec<u8> {
    let mut frame = Frame::new()
        .with_field(TAG_CONTEXT, PREKEY_CONTEXT)
        .with_field(TAG_IDENTITY_PUB, identity.to_bytes())
        .with_field(TAG_PREKEY_X25519, spk.to_bytes().to_vec())
        .with_field(TAG_MLKEM_EK, kem.to_bytes());
    if let Some(opk) = opk {
        frame = frame.with_field(TAG_ONETIME_PREKEY, opk.to_bytes().to_vec());
    }
    frame.encode()
}

impl PrekeyBundle {
    /// Generate a fresh prekey set signed by `identity`, returning the secrets to keep and the
    /// bundle to publish. `with_one_time` adds a single one-time prekey.
    #[must_use]
    pub fn generate(
        identity: &IdentityKeyPair,
        with_one_time: bool,
    ) -> (PrekeySecrets, PrekeyBundle) {
        let spk = X25519SecretKey::generate();
        let (kem_dk, kem_ek) = MlKemSecretKey::generate();
        let opk = with_one_time.then(X25519SecretKey::generate);
        let opk_pub = opk.as_ref().map(X25519SecretKey::public_key);

        let identity_pub = identity.public_key();
        let body = signing_body(&identity_pub, &spk.public_key(), &kem_ek, opk_pub.as_ref());
        let signature = identity.sign(&body);

        let bundle = PrekeyBundle {
            identity: identity_pub,
            signed_prekey: spk.public_key(),
            kem_key: kem_ek,
            one_time_prekey: opk_pub,
            signature,
        };
        let secrets = PrekeySecrets {
            signed_prekey: spk,
            kem_secret: kem_dk,
            one_time_prekey: opk,
        };
        (secrets, bundle)
    }

    /// Serialise the bundle (body fields + identity signature) to wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut frame = Frame::new()
            .with_field(TAG_CONTEXT, PREKEY_CONTEXT)
            .with_field(TAG_IDENTITY_PUB, self.identity.to_bytes())
            .with_field(TAG_PREKEY_X25519, self.signed_prekey.to_bytes().to_vec())
            .with_field(TAG_MLKEM_EK, self.kem_key.to_bytes());
        if let Some(opk) = &self.one_time_prekey {
            frame = frame.with_field(TAG_ONETIME_PREKEY, opk.to_bytes().to_vec());
        }
        frame
            .with_field(TAG_SIGNATURE, self.signature.to_bytes())
            .encode()
    }

    /// Parse and **verify** a bundle. Returns [`CryptoError::BadSignature`] if the identity
    /// signature does not cover the carried keys, so a parsed bundle is always authentic.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let frame = Frame::decode(bytes)?;
        if frame.get(TAG_CONTEXT) != Some(PREKEY_CONTEXT) {
            return Err(CryptoError::malformed("prekey bundle context"));
        }
        let identity = IdentityPublicKey::from_bytes(frame.require(TAG_IDENTITY_PUB)?)?;
        let signed_prekey = X25519PublicKey::from_slice(frame.require(TAG_PREKEY_X25519)?)?;
        let kem_key = MlKemPublicKey::from_slice(frame.require(TAG_MLKEM_EK)?)?;
        let one_time_prekey = match frame.get(TAG_ONETIME_PREKEY) {
            Some(b) => Some(X25519PublicKey::from_slice(b)?),
            None => None,
        };
        let signature = IdentitySignature::from_bytes(frame.require(TAG_SIGNATURE)?)?;

        let body = signing_body(
            &identity,
            &signed_prekey,
            &kem_key,
            one_time_prekey.as_ref(),
        );
        identity.verify(&body, &signature)?;

        Ok(Self {
            identity,
            signed_prekey,
            kem_key,
            one_time_prekey,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_roundtrips_and_verifies() {
        let id = IdentityKeyPair::generate();
        for with_opk in [false, true] {
            let (_secrets, bundle) = PrekeyBundle::generate(&id, with_opk);
            let parsed = PrekeyBundle::decode(&bundle.encode()).unwrap();
            assert_eq!(parsed.identity.to_bytes(), id.public_key().to_bytes());
            assert_eq!(parsed.signed_prekey, bundle.signed_prekey);
            assert_eq!(parsed.one_time_prekey.is_some(), with_opk);
        }
    }

    #[test]
    fn secrets_roundtrip() {
        let id = IdentityKeyPair::generate();
        let (secrets, bundle) = PrekeyBundle::generate(&id, true);
        let parsed = PrekeySecrets::from_bytes(&secrets.to_bytes()).unwrap();
        // Public halves match the published bundle…
        assert_eq!(parsed.signed_prekey.public_key(), bundle.signed_prekey);
        assert!(parsed.one_time_prekey.is_some());
        // …and the restored KEM secret still decapsulates to the bundle's encapsulation key.
        let (ct, ss) = bundle.kem_key.encapsulate();
        assert_eq!(parsed.kem_secret.decapsulate(&ct).unwrap(), ss);
        assert!(PrekeySecrets::from_bytes(b"\x02bad").is_err());
    }

    #[test]
    fn tampered_prekey_is_rejected_on_parse() {
        let id = IdentityKeyPair::generate();
        let (_secrets, bundle) = PrekeyBundle::generate(&id, false);
        // Swap in a different SPK the identity never signed.
        let attacker_spk = X25519SecretKey::generate().public_key();
        let forged = PrekeyBundle {
            signed_prekey: attacker_spk,
            ..bundle.clone()
        };
        assert!(matches!(
            PrekeyBundle::decode(&forged.encode()),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn wrong_identity_signature_is_rejected() {
        let alice = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate();
        let (_s, bundle) = PrekeyBundle::generate(&alice, true);
        // Re-label the bundle as Mallory's without re-signing.
        let forged = PrekeyBundle {
            identity: mallory.public_key(),
            ..bundle
        };
        assert!(PrekeyBundle::decode(&forged.encode()).is_err());
    }
}
