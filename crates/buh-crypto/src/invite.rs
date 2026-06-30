//! One-time, signed invites — buh's primary first-contact mechanism (`doc/design.md` §6.1).
//!
//! An invite is a SimpleX-shape capability: it bundles *where* to reach the inviter (a queue
//! descriptor, carrying the hosting node's CA fingerprint so the recipient pins the right
//! node) with *how* to encrypt to them (a signed [`PrekeyBundle`]), plus a one-time nonce and
//! an expiry, all signed by the inviter's ML-DSA identity. It is wrapped `buh1:<base64url>`
//! for a QR code or paste.
//!
//! [`Invite::parse`] **verifies before it returns**: the outer identity signature must cover
//! the queue, nonce, and expiry, the embedded prekey bundle must verify on its own, and both
//! must name the same identity. A parsed `Invite` is therefore always authentic — there is no
//! way to obtain one whose keys the named identity did not vouch for.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::CryptoError;
use crate::identity::{IdentityKeyPair, IdentityPublicKey, IdentitySignature};
use crate::prekey::PrekeyBundle;
use crate::wire::{
    Frame, TAG_CA_FINGERPRINT, TAG_CONTEXT, TAG_EXPIRY, TAG_IDENTITY_PUB, TAG_INVITE_NONCE,
    TAG_PREKEY_BUNDLE, TAG_QUEUE_ID, TAG_QUEUE_URI, TAG_RELAY_URL, TAG_SIGNATURE,
};

/// Length of the one-time invite nonce (bytes).
pub const INVITE_NONCE_LEN: usize = 16;
/// Length of a node CA fingerprint (bytes).
pub const CA_FINGERPRINT_LEN: usize = 32;
/// The `buh1:` scheme prefix on the wrapped invite string.
pub const INVITE_PREFIX: &str = "buh1:";

const INVITE_CONTEXT: &[u8] = b"buh-invite-v1";

/// Where to reach a contact: an opaque queue on a relay, plus the node CA fingerprint a client
/// pins so it trusts exactly the node hosting the queue (`doc/design.md` §6.1 / Node trust
/// model).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueDescriptor {
    /// The opaque 32-byte queue identifier (the relay's entire addressing surface).
    pub queue_id: [u8; 32],
    /// Base URL of the hosting relay node.
    pub relay_url: String,
    /// The hosting node's CA fingerprint, pinned by the recipient.
    pub ca_fingerprint: [u8; CA_FINGERPRINT_LEN],
}

impl QueueDescriptor {
    fn encode(&self) -> Vec<u8> {
        Frame::new()
            .with_field(TAG_QUEUE_ID, self.queue_id.to_vec())
            .with_field(TAG_RELAY_URL, self.relay_url.as_bytes().to_vec())
            .with_field(TAG_CA_FINGERPRINT, self.ca_fingerprint.to_vec())
            .encode()
    }

    fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let frame = Frame::decode(bytes)?;
        let queue_id: [u8; 32] = frame
            .require(TAG_QUEUE_ID)?
            .try_into()
            .map_err(|_| CryptoError::malformed("queue id"))?;
        let relay_url = core::str::from_utf8(frame.require(TAG_RELAY_URL)?)
            .map_err(|_| CryptoError::malformed("relay url"))?
            .to_owned();
        let ca_fingerprint: [u8; CA_FINGERPRINT_LEN] = frame
            .require(TAG_CA_FINGERPRINT)?
            .try_into()
            .map_err(|_| CryptoError::malformed("ca fingerprint"))?;
        Ok(Self {
            queue_id,
            relay_url,
            ca_fingerprint,
        })
    }
}

/// A one-time signed invite.
#[derive(Clone)]
pub struct Invite {
    /// Where to reach the inviter.
    pub queue: QueueDescriptor,
    /// The inviter's signed prekey bundle (also carries the inviter identity).
    pub bundle: PrekeyBundle,
    /// One-time nonce making the invite single-use / spam-resistant.
    pub nonce: [u8; INVITE_NONCE_LEN],
    /// Expiry, epoch-milliseconds.
    pub expiry_ms: u64,
    signature: IdentitySignature,
}

/// The deterministic byte string the inviter signs and the parser re-checks.
fn signing_body(
    queue: &QueueDescriptor,
    identity: &IdentityPublicKey,
    bundle_bytes: &[u8],
    nonce: &[u8; INVITE_NONCE_LEN],
    expiry_ms: u64,
) -> Vec<u8> {
    Frame::new()
        .with_field(TAG_CONTEXT, INVITE_CONTEXT)
        .with_field(TAG_QUEUE_URI, queue.encode())
        .with_field(TAG_IDENTITY_PUB, identity.to_bytes())
        .with_field(TAG_PREKEY_BUNDLE, bundle_bytes.to_vec())
        .with_field(TAG_INVITE_NONCE, nonce.to_vec())
        .with_field(TAG_EXPIRY, expiry_ms.to_be_bytes().to_vec())
        .encode()
}

impl Invite {
    /// Create a signed invite from the inviter's identity, queue, and freshly-generated prekey
    /// bundle. `nonce` should be unique per invite; `expiry_ms` is an absolute epoch-ms time.
    #[must_use]
    pub fn create(
        identity: &IdentityKeyPair,
        queue: QueueDescriptor,
        bundle: PrekeyBundle,
        nonce: [u8; INVITE_NONCE_LEN],
        expiry_ms: u64,
    ) -> Self {
        let bundle_bytes = bundle.encode();
        let body = signing_body(
            &queue,
            &identity.public_key(),
            &bundle_bytes,
            &nonce,
            expiry_ms,
        );
        let signature = identity.sign(&body);
        Self {
            queue,
            bundle,
            nonce,
            expiry_ms,
            signature,
        }
    }

    /// Serialise to wire bytes (body fields + identity signature).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        Frame::new()
            .with_field(TAG_CONTEXT, INVITE_CONTEXT)
            .with_field(TAG_QUEUE_URI, self.queue.encode())
            .with_field(TAG_IDENTITY_PUB, self.bundle.identity.to_bytes())
            .with_field(TAG_PREKEY_BUNDLE, self.bundle.encode())
            .with_field(TAG_INVITE_NONCE, self.nonce.to_vec())
            .with_field(TAG_EXPIRY, self.expiry_ms.to_be_bytes().to_vec())
            .with_field(TAG_SIGNATURE, self.signature.to_bytes())
            .encode()
    }

    /// The `buh1:<base64url>` string form for a QR code or paste.
    #[must_use]
    pub fn to_uri(&self) -> String {
        format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(self.encode()))
    }

    /// Parse and **verify** a `buh1:` invite. Returns an error unless the inviter's signature
    /// covers the queue/nonce/expiry, the embedded bundle verifies, and both name the same
    /// identity. Does **not** check expiry against a clock — the caller does that with its own
    /// time source (the crate stays clock-free for portability/wasm).
    pub fn parse(uri: &str) -> Result<Self, CryptoError> {
        let b64 = uri
            .strip_prefix(INVITE_PREFIX)
            .ok_or(CryptoError::malformed("invite scheme"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| CryptoError::malformed("invite base64"))?;
        Self::decode(&bytes)
    }

    /// Parse and verify raw invite bytes (the inner of [`Self::parse`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let frame = Frame::decode(bytes)?;
        if frame.get(TAG_CONTEXT) != Some(INVITE_CONTEXT) {
            return Err(CryptoError::malformed("invite context"));
        }
        let queue = QueueDescriptor::decode(frame.require(TAG_QUEUE_URI)?)?;
        let identity = IdentityPublicKey::from_bytes(frame.require(TAG_IDENTITY_PUB)?)?;
        let bundle_bytes = frame.require(TAG_PREKEY_BUNDLE)?;
        let nonce: [u8; INVITE_NONCE_LEN] = frame
            .require(TAG_INVITE_NONCE)?
            .try_into()
            .map_err(|_| CryptoError::malformed("invite nonce"))?;
        let expiry_bytes: [u8; 8] = frame
            .require(TAG_EXPIRY)?
            .try_into()
            .map_err(|_| CryptoError::malformed("invite expiry"))?;
        let expiry_ms = u64::from_be_bytes(expiry_bytes);
        let signature = IdentitySignature::from_bytes(frame.require(TAG_SIGNATURE)?)?;

        // The embedded bundle verifies on its own decode (verify-on-parse).
        let bundle = PrekeyBundle::decode(bundle_bytes)?;
        // The invite must name the same identity as the bundle it carries.
        if bundle.identity.to_bytes() != identity.to_bytes() {
            return Err(CryptoError::malformed("invite identity mismatch"));
        }
        // The outer invite signature must cover queue + nonce + expiry.
        let body = signing_body(&queue, &identity, bundle_bytes, &nonce, expiry_ms);
        identity.verify(&body, &signature)?;

        Ok(Self {
            queue,
            bundle,
            nonce,
            expiry_ms,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_queue() -> QueueDescriptor {
        QueueDescriptor {
            queue_id: [0x11; 32],
            relay_url: "https://relay.example:8443".to_owned(),
            ca_fingerprint: [0x22; CA_FINGERPRINT_LEN],
        }
    }

    fn sample_invite() -> (IdentityKeyPair, Invite) {
        let id = IdentityKeyPair::generate();
        let (_secrets, bundle) = PrekeyBundle::generate(&id, true);
        let invite = Invite::create(
            &id,
            sample_queue(),
            bundle,
            [0x33; INVITE_NONCE_LEN],
            1_900_000_000_000,
        );
        (id, invite)
    }

    #[test]
    fn uri_roundtrips_and_verifies() {
        let (_id, invite) = sample_invite();
        let uri = invite.to_uri();
        assert!(uri.starts_with("buh1:"));
        let parsed = Invite::parse(&uri).unwrap();
        assert_eq!(parsed.queue, sample_queue());
        assert_eq!(parsed.nonce, [0x33; INVITE_NONCE_LEN]);
        assert_eq!(parsed.expiry_ms, 1_900_000_000_000);
        assert_eq!(
            parsed.bundle.identity.to_bytes(),
            invite.bundle.identity.to_bytes()
        );
    }

    #[test]
    fn tampered_queue_is_rejected() {
        let (_id, invite) = sample_invite();
        let mut forged = invite.clone();
        forged.queue.ca_fingerprint = [0xff; CA_FINGERPRINT_LEN]; // re-point to an attacker node
        assert!(matches!(
            Invite::decode(&forged.encode()),
            Err(CryptoError::BadSignature)
        ));
    }

    #[test]
    fn swapped_bundle_identity_is_rejected() {
        // An attacker splices their own (validly self-signed) bundle into Alice's invite.
        let (_alice, invite) = sample_invite();
        let mallory = IdentityKeyPair::generate();
        let (_s, mallory_bundle) = PrekeyBundle::generate(&mallory, false);
        let forged = Invite {
            bundle: mallory_bundle,
            ..invite
        };
        // The bundle still verifies on its own, but its identity no longer matches the invite's.
        assert!(Invite::decode(&forged.encode()).is_err());
    }

    #[test]
    fn rejects_bad_scheme_and_base64() {
        assert!(Invite::parse("nope:abc").is_err());
        assert!(Invite::parse("buh1:!!!!").is_err());
    }
}
