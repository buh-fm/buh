//! PQXDH — the hybrid, authenticated handshake that turns a published [`PrekeyBundle`] into a
//! shared 32-byte root key for the Double Ratchet (`doc/design.md` §5.2).
//!
//! It mixes **two** secrets into the root: an X25519 Diffie-Hellman (initiator ephemeral ×
//! responder prekey, plus the one-time prekey when present) **and** an ML-KEM-768
//! encapsulation. An adversary must break *both* X25519 *and* ML-KEM to recover the session —
//! so traffic recorded today survives a future quantum computer.
//!
//! Identities are ML-DSA (signing, not DH), so authentication is by signature, not by an
//! identity DH: the responder's whole bundle is verified on parse, and the initiator signs the
//! full transcript (every public value on both sides) with its identity key. The responder
//! re-derives that transcript and checks the signature before deriving the root, binding the
//! handshake to both parties and to the exact keys used.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;
use crate::identity::{IdentityKeyPair, IdentityPublicKey, IdentitySignature};
use crate::kem::{X25519PublicKey, X25519SecretKey};
use crate::prekey::{PrekeyBundle, PrekeySecrets};
use crate::wire::{
    Frame, TAG_CONTEXT, TAG_EPHEMERAL_X25519, TAG_IDENTITY_PUB, TAG_KEM_CT, TAG_MLKEM_EK,
    TAG_ONETIME_PREKEY, TAG_PREKEY_X25519, TAG_SIGNATURE,
};

/// Domain-separation label for the HKDF that derives the root key.
const KDF_CONTEXT: &[u8] = b"buh-pqxdh-root-v1";
/// Domain-separation label for the signed handshake transcript.
const TRANSCRIPT_CONTEXT: &[u8] = b"buh-pqxdh-transcript-v1";

/// Length of the derived session root key.
pub const ROOT_KEY_LEN: usize = 32;

/// The initiator's first flight: everything the responder needs to derive the same root, plus
/// the initiator's identity and a signature binding the whole transcript.
pub struct InitialMessage {
    /// The initiator's ML-DSA identity public key.
    pub initiator_identity: IdentityPublicKey,
    /// The initiator's ephemeral X25519 public key.
    pub ephemeral: X25519PublicKey,
    /// The ML-KEM ciphertext encapsulated to the responder's KEM key.
    pub kem_ciphertext: Vec<u8>,
    /// ML-DSA signature over the transcript, by the initiator identity.
    signature: IdentitySignature,
}

/// Bind every public handshake value — both bundles' keys and the initiator's ephemerals —
/// into one deterministic transcript. Signed by the initiator, fed as HKDF info, and
/// recomputed by the responder; any mismatch breaks both the signature check and the KDF.
fn transcript(
    responder: &ResponderView,
    initiator_identity: &IdentityPublicKey,
    ephemeral: &X25519PublicKey,
    kem_ciphertext: &[u8],
) -> Vec<u8> {
    let mut frame = Frame::new()
        .with_field(TAG_CONTEXT, TRANSCRIPT_CONTEXT)
        // Responder side (the published bundle).
        .with_field(TAG_IDENTITY_PUB, responder.identity.to_bytes())
        .with_field(
            TAG_PREKEY_X25519,
            responder.signed_prekey.to_bytes().to_vec(),
        )
        .with_field(TAG_MLKEM_EK, responder.kem_key_bytes.clone());
    if let Some(opk) = &responder.one_time_prekey {
        frame = frame.with_field(TAG_ONETIME_PREKEY, opk.to_bytes().to_vec());
    }
    // Initiator side.
    frame
        .with_field(TAG_IDENTITY_PUB, initiator_identity.to_bytes())
        .with_field(TAG_EPHEMERAL_X25519, ephemeral.to_bytes().to_vec())
        .with_field(TAG_KEM_CT, kem_ciphertext.to_vec())
        .encode()
}

/// The responder public values referenced by the transcript (a thin view over a bundle).
struct ResponderView {
    identity: IdentityPublicKey,
    signed_prekey: X25519PublicKey,
    kem_key_bytes: Vec<u8>,
    one_time_prekey: Option<X25519PublicKey>,
}

impl ResponderView {
    fn from_bundle(bundle: &PrekeyBundle) -> Self {
        Self {
            identity: bundle.identity.clone(),
            signed_prekey: bundle.signed_prekey,
            kem_key_bytes: bundle.kem_key.to_bytes(),
            one_time_prekey: bundle.one_time_prekey,
        }
    }
}

/// Derive the 32-byte root from the concatenated secrets and the transcript.
fn derive_root(ikm: &[u8], transcript: &[u8]) -> [u8; ROOT_KEY_LEN] {
    // salt = domain label; info = transcript. HKDF-SHA256, the same chain hash the ratchet uses.
    let hk = Hkdf::<Sha256>::new(Some(KDF_CONTEXT), ikm);
    let mut root = [0u8; ROOT_KEY_LEN];
    hk.expand(transcript, &mut root)
        .expect("32 < 255*32 HKDF output");
    root
}

/// Run the **initiator** side against a verified `responder` bundle. Returns the message to
/// send and the shared root key. The responder's `signed_prekey` (its ratchet public) is the
/// initiator's initial remote ratchet key — surfaced via [`InitialMessage`]/the caller.
#[must_use]
pub fn initiate(
    initiator: &IdentityKeyPair,
    responder: &PrekeyBundle,
) -> (InitialMessage, [u8; ROOT_KEY_LEN]) {
    let ephemeral = X25519SecretKey::generate();
    let dh_spk = ephemeral.diffie_hellman(&responder.signed_prekey);
    let (kem_ciphertext, ss) = responder.kem_key.encapsulate();

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&dh_spk);
    if let Some(opk) = &responder.one_time_prekey {
        ikm.extend_from_slice(&ephemeral.diffie_hellman(opk));
    }
    ikm.extend_from_slice(&ss);

    let view = ResponderView::from_bundle(responder);
    let initiator_identity = initiator.public_key();
    let script = transcript(
        &view,
        &initiator_identity,
        &ephemeral.public_key(),
        &kem_ciphertext,
    );
    let root = derive_root(&ikm, &script);
    let signature = initiator.sign(&script);

    let message = InitialMessage {
        initiator_identity,
        ephemeral: ephemeral.public_key(),
        kem_ciphertext,
        signature,
    };
    (message, root)
}

/// Run the **responder** side: verify the initiator's signature over the transcript, then
/// re-derive the identical root key from the responder's own secrets. `bundle` is the
/// responder's own published bundle, `secrets` its retained secret halves.
pub fn respond(
    bundle: &PrekeyBundle,
    secrets: &PrekeySecrets,
    message: &InitialMessage,
) -> Result<[u8; ROOT_KEY_LEN], CryptoError> {
    let view = ResponderView::from_bundle(bundle);
    let script = transcript(
        &view,
        &message.initiator_identity,
        &message.ephemeral,
        &message.kem_ciphertext,
    );
    // Authenticate the initiator over the exact transcript before using any of it.
    message
        .initiator_identity
        .verify(&script, &message.signature)?;

    let dh_spk = secrets.signed_prekey.diffie_hellman(&message.ephemeral);
    let ss = secrets.kem_secret.decapsulate(&message.kem_ciphertext)?;

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&dh_spk);
    if let Some(opk) = &secrets.one_time_prekey {
        ikm.extend_from_slice(&opk.diffie_hellman(&message.ephemeral));
    }
    ikm.extend_from_slice(&ss);

    Ok(derive_root(&ikm, &script))
}

impl InitialMessage {
    /// Serialise the first flight to wire bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        Frame::new()
            .with_field(TAG_CONTEXT, TRANSCRIPT_CONTEXT)
            .with_field(TAG_IDENTITY_PUB, self.initiator_identity.to_bytes())
            .with_field(TAG_EPHEMERAL_X25519, self.ephemeral.to_bytes().to_vec())
            .with_field(TAG_KEM_CT, self.kem_ciphertext.clone())
            .with_field(TAG_SIGNATURE, self.signature.to_bytes())
            .encode()
    }

    /// Parse the first flight. The signature is checked later by [`respond`] against the full
    /// transcript, so this only validates structure.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let frame = Frame::decode(bytes)?;
        if frame.get(TAG_CONTEXT) != Some(TRANSCRIPT_CONTEXT) {
            return Err(CryptoError::malformed("handshake context"));
        }
        Ok(Self {
            initiator_identity: IdentityPublicKey::from_bytes(frame.require(TAG_IDENTITY_PUB)?)?,
            ephemeral: X25519PublicKey::from_slice(frame.require(TAG_EPHEMERAL_X25519)?)?,
            kem_ciphertext: frame.require(TAG_KEM_CT)?.to_vec(),
            signature: IdentitySignature::from_bytes(frame.require(TAG_SIGNATURE)?)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake(with_opk: bool) -> ([u8; ROOT_KEY_LEN], [u8; ROOT_KEY_LEN]) {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (bob_secrets, bob_bundle) = PrekeyBundle::generate(&bob, with_opk);
        let (msg, alice_root) = initiate(&alice, &bob_bundle);
        // Exercise the wire round-trip of the first flight too.
        let msg = InitialMessage::decode(&msg.encode()).unwrap();
        let bob_root = respond(&bob_bundle, &bob_secrets, &msg).unwrap();
        (alice_root, bob_root)
    }

    #[test]
    fn both_sides_agree_with_and_without_opk() {
        for with_opk in [false, true] {
            let (a, b) = handshake(with_opk);
            assert_eq!(a, b);
            assert_ne!(a, [0u8; ROOT_KEY_LEN]);
        }
    }

    #[test]
    fn forged_initiator_signature_is_rejected() {
        let alice = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (bob_secrets, bob_bundle) = PrekeyBundle::generate(&bob, true);
        let (mut msg, _root) = initiate(&alice, &bob_bundle);
        // Claim to be Mallory while carrying Alice's signature.
        msg.initiator_identity = mallory.public_key();
        assert_eq!(
            respond(&bob_bundle, &bob_secrets, &msg),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn tampered_ciphertext_breaks_agreement() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let (bob_secrets, bob_bundle) = PrekeyBundle::generate(&bob, false);
        let (mut msg, _alice_root) = initiate(&alice, &bob_bundle);
        // Flip a ciphertext byte: the signature no longer covers it → rejected.
        msg.kem_ciphertext[0] ^= 0x01;
        assert!(respond(&bob_bundle, &bob_secrets, &msg).is_err());
    }
}
