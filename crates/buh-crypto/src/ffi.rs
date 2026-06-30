//! The `wasm-bindgen` FFI surface, compiled only under the `wasm` feature for the web client.
//!
//! Two layers live here. The `*_self_test` helpers run the native KATs *inside the browser* so
//! the web app can confirm the whole crypto stack (TLV codec, XChaCha20-Poly1305, ML-DSA-65
//! over the `wasm_js` getrandom backend) behaves identically to native. On top of that is the
//! **session facade**: a small, envelope-oriented, *state-returning* API. Every mutating call
//! takes the relevant opaque state blob(s) and returns new one(s); the Rust side keeps no
//! state across the boundary, so the JS [`KeyStore`](../../web) owns persistence. State blobs
//! carry secret material — the web layer seals them at rest.

use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::identity::{IdentityKeyPair, SEED_LEN};
use crate::invite::{CA_FINGERPRINT_LEN, INVITE_NONCE_LEN, Invite, QueueDescriptor};
use crate::pqxdh::{InitialMessage, initiate, respond};
use crate::prekey::{PrekeyBundle, PrekeySecrets};
use crate::ratchet::RatchetState;
use crate::{aead, wire};

/// Length of an opaque queue identifier carried in an invite (bytes).
const QUEUE_ID_LEN: usize = 32;

/// Map a crate error to a JS exception (message only — never secret state).
fn js(err: crate::CryptoError) -> JsError {
    JsError::new(&err.to_string())
}

/// Coerce a slice to a fixed-size array, erroring with `what` on the wrong length.
fn fixed<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], JsError> {
    bytes
        .try_into()
        .map_err(|_| JsError::new(&format!("expected {N}-byte {what}")))
}

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

// ===========================================================================================
// Session facade — state-returning. Blobs are opaque to JS; the KeyStore persists them.
// ===========================================================================================

/// Generate a fresh identity. Returns the identity state blob (the 32-byte seed — the private
/// key; the JS layer seals it). The user *is* this key.
#[wasm_bindgen]
#[must_use]
pub fn generate_identity() -> Vec<u8> {
    IdentityKeyPair::generate().to_seed().to_vec()
}

/// The ML-DSA public key for an identity state — a stable fingerprint to show the user.
#[wasm_bindgen]
pub fn identity_public_key(identity: &[u8]) -> Result<Vec<u8>, JsError> {
    let id = IdentityKeyPair::from_seed(&fixed::<SEED_LEN>(identity, "identity")?);
    Ok(id.public_key().to_bytes())
}

/// A freshly generated prekey set: the secret state to persist, and the public bundle to
/// publish (embed in an invite).
#[wasm_bindgen]
pub struct PrekeyMaterial {
    secrets: Vec<u8>,
    bundle: Vec<u8>,
}

#[wasm_bindgen]
impl PrekeyMaterial {
    /// The secret state blob (persist, sealed).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn secrets(&self) -> Vec<u8> {
        self.secrets.clone()
    }

    /// The public, signed prekey bundle.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bundle(&self) -> Vec<u8> {
        self.bundle.clone()
    }
}

/// Generate a publishable prekey bundle (with a one-time prekey) for an identity.
#[wasm_bindgen]
pub fn publishable_prekey_bundle(identity: &[u8]) -> Result<PrekeyMaterial, JsError> {
    let id = IdentityKeyPair::from_seed(&fixed::<SEED_LEN>(identity, "identity")?);
    let (secrets, bundle) = PrekeyBundle::generate(&id, true);
    Ok(PrekeyMaterial {
        secrets: secrets.to_bytes(),
        bundle: bundle.encode(),
    })
}

/// Create a `buh1:` invite: the inviter's queue (with the hosting node's CA fingerprint to
/// pin) plus their published `bundle`, signed by their identity.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn create_invite(
    identity: &[u8],
    queue_id: &[u8],
    relay_url: String,
    ca_fingerprint: &[u8],
    bundle: &[u8],
    nonce: &[u8],
    expiry_ms: f64,
) -> Result<String, JsError> {
    let id = IdentityKeyPair::from_seed(&fixed::<SEED_LEN>(identity, "identity")?);
    let queue = QueueDescriptor {
        queue_id: fixed::<QUEUE_ID_LEN>(queue_id, "queue id")?,
        relay_url,
        ca_fingerprint: fixed::<CA_FINGERPRINT_LEN>(ca_fingerprint, "ca fingerprint")?,
    };
    let bundle = PrekeyBundle::decode(bundle).map_err(js)?;
    let nonce = fixed::<INVITE_NONCE_LEN>(nonce, "invite nonce")?;
    let invite = Invite::create(&id, queue, bundle, nonce, expiry_ms as u64);
    Ok(invite.to_uri())
}

/// A verified, parsed invite. All fields are authentic (the invite verified on parse).
#[wasm_bindgen]
pub struct ParsedInvite {
    queue_id: Vec<u8>,
    relay_url: String,
    ca_fingerprint: Vec<u8>,
    identity_public_key: Vec<u8>,
    bundle: Vec<u8>,
    expiry_ms: f64,
}

#[wasm_bindgen]
impl ParsedInvite {
    /// The inviter's relay queue id.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn queue_id(&self) -> Vec<u8> {
        self.queue_id.clone()
    }
    /// The inviter's relay base URL.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn relay_url(&self) -> String {
        self.relay_url.clone()
    }
    /// The hosting node's CA fingerprint to pin.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn ca_fingerprint(&self) -> Vec<u8> {
        self.ca_fingerprint.clone()
    }
    /// The inviter's ML-DSA identity public key.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn identity_public_key(&self) -> Vec<u8> {
        self.identity_public_key.clone()
    }
    /// The inviter's prekey bundle (feed to [`initiate_session`]).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn bundle(&self) -> Vec<u8> {
        self.bundle.clone()
    }
    /// Invite expiry, epoch-milliseconds (the caller checks it against its own clock).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn expiry_ms(&self) -> f64 {
        self.expiry_ms
    }
}

/// Parse and verify a `buh1:` invite. Throws unless the signature covers the queue/keys and
/// the embedded bundle verifies.
#[wasm_bindgen]
pub fn parse_invite(uri: &str) -> Result<ParsedInvite, JsError> {
    let invite = Invite::parse(uri).map_err(js)?;
    Ok(ParsedInvite {
        queue_id: invite.queue.queue_id.to_vec(),
        relay_url: invite.queue.relay_url.clone(),
        ca_fingerprint: invite.queue.ca_fingerprint.to_vec(),
        identity_public_key: invite.bundle.identity.to_bytes(),
        bundle: invite.bundle.encode(),
        expiry_ms: invite.expiry_ms as f64,
    })
}

/// The initiator's output: the session state to persist and the handshake first-flight to send
/// to the responder's queue (ahead of the first ciphertext).
#[wasm_bindgen]
pub struct InitiatedSession {
    session: Vec<u8>,
    initial_message: Vec<u8>,
}

#[wasm_bindgen]
impl InitiatedSession {
    /// The session state blob (persist, sealed).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn session(&self) -> Vec<u8> {
        self.session.clone()
    }
    /// The PQXDH first-flight message to deliver before the first ciphertext.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn initial_message(&self) -> Vec<u8> {
        self.initial_message.clone()
    }
}

/// Start a session as the **initiator** against a verified prekey `bundle` (from an invite).
/// Returns the session state and the handshake first-flight to send.
#[wasm_bindgen]
pub fn initiate_session(identity: &[u8], bundle: &[u8]) -> Result<InitiatedSession, JsError> {
    let id = IdentityKeyPair::from_seed(&fixed::<SEED_LEN>(identity, "identity")?);
    let bundle = PrekeyBundle::decode(bundle).map_err(js)?;
    let (message, root) = initiate(&id, &bundle);
    let session = RatchetState::initiator(root, bundle.signed_prekey);
    Ok(InitiatedSession {
        session: session.to_bytes(),
        initial_message: message.encode(),
    })
}

/// Complete a session as the **responder** from one's own prekey `secrets` + published
/// `bundle` and the initiator's `initial_message`. Returns the session state. Throws if the
/// initiator's signature does not verify.
#[wasm_bindgen]
pub fn accept_session(
    secrets: &[u8],
    bundle: &[u8],
    initial_message: &[u8],
) -> Result<Vec<u8>, JsError> {
    let secrets = PrekeySecrets::from_bytes(secrets).map_err(js)?;
    let bundle = PrekeyBundle::decode(bundle).map_err(js)?;
    let message = InitialMessage::decode(initial_message).map_err(js)?;
    let root = respond(&bundle, &secrets, &message).map_err(js)?;
    let session = RatchetState::responder(root, secrets.signed_prekey);
    Ok(session.to_bytes())
}

/// The result of encrypting: the advanced session state and the wire message to send.
#[wasm_bindgen]
pub struct EncryptedMessage {
    session: Vec<u8>,
    message: Vec<u8>,
}

#[wasm_bindgen]
impl EncryptedMessage {
    /// The advanced session state blob (persist, sealed).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn session(&self) -> Vec<u8> {
        self.session.clone()
    }
    /// The ratchet wire message to deliver.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
}

/// Encrypt `plaintext` in `session`, returning the advanced session and the wire message.
#[wasm_bindgen]
pub fn encrypt_message(session: &[u8], plaintext: &[u8]) -> Result<EncryptedMessage, JsError> {
    let mut state = RatchetState::from_bytes(session).map_err(js)?;
    let message = state.encrypt(plaintext).map_err(js)?;
    Ok(EncryptedMessage {
        session: state.to_bytes(),
        message,
    })
}

/// The result of decrypting: the advanced session state and the recovered plaintext.
#[wasm_bindgen]
pub struct DecryptedMessage {
    session: Vec<u8>,
    plaintext: Vec<u8>,
}

#[wasm_bindgen]
impl DecryptedMessage {
    /// The advanced session state blob (persist, sealed).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn session(&self) -> Vec<u8> {
        self.session.clone()
    }
    /// The recovered plaintext.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn plaintext(&self) -> Vec<u8> {
        self.plaintext.clone()
    }
}

/// Decrypt a wire `message` in `session`, returning the advanced session and the plaintext.
#[wasm_bindgen]
pub fn decrypt_message(session: &[u8], message: &[u8]) -> Result<DecryptedMessage, JsError> {
    let mut state = RatchetState::from_bytes(session).map_err(js)?;
    let plaintext = state.decrypt(message).map_err(js)?;
    Ok(DecryptedMessage {
        session: state.to_bytes(),
        plaintext,
    })
}
