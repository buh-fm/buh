//! The version-1 frame: a 2-byte prelude, a capability-flags varint, then length-prefixed
//! TLV fields.
//!
//! ```text
//! ┌────────┬──────────┬───────────┬───────────────────────────────────────┐
//! │ MAGIC  │ VERSION  │ flags     │ fields…                                │
//! │ 0xB0   │ 0x01     │ varint    │ (tag:varint  len:varint  value:len)*   │
//! └────────┴──────────┴───────────┴───────────────────────────────────────┘
//! ```
//!
//! Nothing is ever a bare positional struct: every field is tag-length-value, so new fields
//! can be added and unknown ones skipped without a wire break. The reserved PQ tags
//! (`TAG_SPQR_CHUNK`/`TAG_PQ_EPOCH`/`TAG_PQ_KEM_CT`) are declared here and **never emitted**
//! in v1 — that is the literal `doc/design.md` §5.3 "add PQ rekey later without a
//! wire-format break" contract. A messaging decoder skips unknown tags; a handshake decoder
//! calls [`Frame::reject_reserved_pq`] so an attacker can't smuggle an unparsed PQ field past
//! the transcript.
//!
//! The prelude and flags are exposed verbatim as the AEAD AAD ([`Frame::aad`]) so that any
//! version or capability downgrade is authenticated rather than silently accepted.

use std::ops::RangeInclusive;

use super::codec::{Reader, write_varint};
use super::{MAGIC, WIRE_VERSION, WireError};

// --- Field tags. Stable on-wire identifiers; an emitted tag is never renumbered. ---

/// ML-DSA identity public key.
pub const TAG_IDENTITY_PUB: u64 = 0x01;
/// Signed prekey bundle.
pub const TAG_PREKEY_BUNDLE: u64 = 0x02;
/// Queue descriptor (relay URI + node CA fingerprint for pinning).
pub const TAG_QUEUE_URI: u64 = 0x03;
/// One-time invite nonce (spam-proofing / replay defence).
pub const TAG_INVITE_NONCE: u64 = 0x04;
/// Expiry, epoch-milliseconds, varint.
pub const TAG_EXPIRY: u64 = 0x05;
/// ML-DSA signature over the preceding body.
pub const TAG_SIGNATURE: u64 = 0x06;

// --- Prekey-bundle / handshake fields (Phase 3). ---

/// Domain-separation context label, always the first signed field.
pub const TAG_CONTEXT: u64 = 0x07;
/// A long-lived signed X25519 prekey (the responder's SPK).
pub const TAG_PREKEY_X25519: u64 = 0x08;
/// An ML-KEM-768 encapsulation (public) key.
pub const TAG_MLKEM_EK: u64 = 0x09;
/// A one-time X25519 prekey (optional).
pub const TAG_ONETIME_PREKEY: u64 = 0x0a;
/// The initiator's ephemeral X25519 public key in a handshake.
pub const TAG_EPHEMERAL_X25519: u64 = 0x0b;
/// The handshake ML-KEM ciphertext (initial PQXDH encapsulation — distinct from the reserved
/// [`TAG_PQ_KEM_CT`], which is for the future *rekey* layer).
pub const TAG_KEM_CT: u64 = 0x0c;

// --- Double Ratchet header fields (Phase 3). ---

/// Sender's current ratchet DH public key.
pub const TAG_RATCHET_DH: u64 = 0x10;
/// Number of messages in the previous sending chain.
pub const TAG_RATCHET_PN: u64 = 0x11;
/// Message number in the current sending chain.
pub const TAG_RATCHET_N: u64 = 0x12;
/// Sealed message ciphertext.
pub const TAG_CIPHERTEXT: u64 = 0x13;

// --- Reserved post-quantum rekey tags (`doc/design.md` §5.3). Declared, never emitted in v1. ---

/// SPQR rekey chunk (reserved).
pub const TAG_SPQR_CHUNK: u64 = 0x20;
/// PQ ratchet epoch counter (reserved).
pub const TAG_PQ_EPOCH: u64 = 0x21;
/// ML-KEM ciphertext for a PQ rekey (reserved).
pub const TAG_PQ_KEM_CT: u64 = 0x22;

/// Inclusive tag range reserved for the future PQ-rekey layer. No v1 encoder emits these.
pub const PQ_RESERVED_TAGS: RangeInclusive<u64> = 0x20..=0x2f;

// --- Capability flags (a bitset carried as a varint, bound into the AAD). ---

/// The frame is a handshake / session-initiation message (vs. an ongoing ratchet message).
pub const FLAG_HANDSHAKE: u64 = 0x01;
/// Reserved: a PQ rekey is present. Never set by a v1 encoder.
pub const FLAG_PQ_REKEY: u64 = 0x02;

/// A single tag-length-value field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// Field identifier.
    pub tag: u64,
    /// Raw field bytes (opaque to the codec).
    pub value: Vec<u8>,
}

/// A decoded or to-be-encoded version-1 frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    /// Capability-flags bitset.
    pub flags: u64,
    /// TLV fields, in emission order.
    pub fields: Vec<Field>,
}

impl Frame {
    /// An empty frame with no flags set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set capability flag bits (OR-ed in). Builder-style.
    #[must_use]
    pub fn with_flags(mut self, flags: u64) -> Self {
        self.flags |= flags;
        self
    }

    /// Append a field. Builder-style.
    #[must_use]
    pub fn with_field(mut self, tag: u64, value: impl Into<Vec<u8>>) -> Self {
        self.fields.push(Field {
            tag,
            value: value.into(),
        });
        self
    }

    /// Whether a flag bit is set.
    #[must_use]
    pub fn has_flag(&self, flag: u64) -> bool {
        self.flags & flag != 0
    }

    /// The first field carrying `tag`, if any.
    #[must_use]
    pub fn get(&self, tag: u64) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|f| f.tag == tag)
            .map(|f| f.value.as_slice())
    }

    /// The first field carrying `tag`, or [`WireError::MissingField`].
    pub fn require(&self, tag: u64) -> Result<&[u8], WireError> {
        self.get(tag).ok_or(WireError::MissingField(tag))
    }

    /// Reject any reserved PQ tag. Call this in the **handshake** context, where an unknown
    /// PQ field must abort rather than be silently skipped (`doc/design.md` §5.3).
    pub fn reject_reserved_pq(&self) -> Result<(), WireError> {
        for f in &self.fields {
            if PQ_RESERVED_TAGS.contains(&f.tag) {
                return Err(WireError::ReservedTag(f.tag));
            }
        }
        Ok(())
    }

    /// The AEAD additional-authenticated-data: prelude + flags, verbatim. Binding this into
    /// the AEAD authenticates the version and capability flags against downgrade.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(2 + super::codec::MAX_VARINT_LEN);
        aad.push(MAGIC);
        aad.push(WIRE_VERSION);
        write_varint(&mut aad, self.flags);
        aad
    }

    /// Serialise to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(MAGIC);
        out.push(WIRE_VERSION);
        write_varint(&mut out, self.flags);
        for f in &self.fields {
            write_varint(&mut out, f.tag);
            write_varint(&mut out, f.value.len() as u64);
            out.extend_from_slice(&f.value);
        }
        out
    }

    /// Parse bytes into a frame. Validates the prelude, then reads TLV fields until input is
    /// exhausted. Never panics or over-allocates on hostile input.
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(buf);
        let magic = r.read_u8()?;
        if magic != MAGIC {
            return Err(WireError::BadMagic(magic));
        }
        let version = r.read_u8()?;
        if version != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }
        let flags = r.read_varint()?;
        let mut fields = Vec::new();
        while !r.is_empty() {
            let tag = r.read_varint()?;
            let len = r.read_varint()?;
            let len = usize::try_from(len).map_err(|_| WireError::FieldTooLong)?;
            // Guard against a corrupt length triggering a huge allocation before the read.
            if len > r.remaining() {
                return Err(WireError::UnexpectedEof);
            }
            let value = r.read_bytes(len)?.to_vec();
            fields.push(Field { tag, value });
        }
        Ok(Self { flags, fields })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_bytes() {
        let frame = Frame::new()
            .with_flags(FLAG_HANDSHAKE)
            .with_field(TAG_IDENTITY_PUB, vec![0xaa, 0xbb]);
        // B0 01 | flags=01 | tag=01 len=02 aa bb
        assert_eq!(
            frame.encode(),
            vec![0xB0, 0x01, 0x01, 0x01, 0x02, 0xaa, 0xbb]
        );
    }

    #[test]
    fn aad_is_prelude_plus_flags() {
        let frame = Frame::new().with_flags(FLAG_HANDSHAKE);
        assert_eq!(frame.aad(), vec![0xB0, 0x01, 0x01]);
    }

    #[test]
    fn roundtrips_with_multiple_fields() {
        let frame = Frame::new()
            .with_flags(FLAG_HANDSHAKE)
            .with_field(TAG_IDENTITY_PUB, vec![1, 2, 3])
            .with_field(TAG_SIGNATURE, vec![9; 64])
            .with_field(TAG_EXPIRY, Vec::new());
        let bytes = frame.encode();
        let back = Frame::decode(&bytes).unwrap();
        assert_eq!(back, frame);
        assert_eq!(back.require(TAG_IDENTITY_PUB).unwrap(), &[1, 2, 3]);
        assert_eq!(back.get(TAG_EXPIRY).unwrap(), &[] as &[u8]);
        assert!(back.has_flag(FLAG_HANDSHAKE));
        assert!(!back.has_flag(FLAG_PQ_REKEY));
    }

    #[test]
    fn rejects_bad_magic_and_version() {
        assert_eq!(Frame::decode(&[0x00, 0x01]), Err(WireError::BadMagic(0x00)));
        assert_eq!(
            Frame::decode(&[0xB0, 0x02]),
            Err(WireError::UnsupportedVersion(0x02))
        );
        assert_eq!(Frame::decode(&[]), Err(WireError::UnexpectedEof));
    }

    #[test]
    fn truncated_field_is_rejected_not_panicked() {
        // Claims a 200-byte field but supplies none.
        let bytes = [0xB0, 0x01, 0x00, TAG_SIGNATURE as u8, 0xc8, 0x01];
        assert_eq!(Frame::decode(&bytes), Err(WireError::UnexpectedEof));
    }

    #[test]
    fn missing_required_field() {
        let frame = Frame::new();
        assert_eq!(
            frame.require(TAG_SIGNATURE),
            Err(WireError::MissingField(TAG_SIGNATURE))
        );
    }

    #[test]
    fn reserved_pq_skipped_in_messaging_rejected_in_handshake() {
        // A frame carrying a reserved PQ tag decodes (messaging skips unknown tags)…
        let frame = Frame::new().with_field(TAG_PQ_EPOCH, vec![0x07]);
        let back = Frame::decode(&frame.encode()).unwrap();
        assert_eq!(back.get(TAG_PQ_EPOCH).unwrap(), &[0x07]);
        // …but the handshake context refuses it.
        assert_eq!(
            back.reject_reserved_pq(),
            Err(WireError::ReservedTag(TAG_PQ_EPOCH))
        );
        // A clean frame passes the handshake gate.
        assert!(
            Frame::new()
                .with_field(TAG_IDENTITY_PUB, vec![1])
                .reject_reserved_pq()
                .is_ok()
        );
    }

    #[test]
    fn v1_encoder_never_emits_reserved_tags() {
        // Sanity: the tags a normal encoder uses are all outside the reserved range.
        for tag in [
            TAG_IDENTITY_PUB,
            TAG_PREKEY_BUNDLE,
            TAG_QUEUE_URI,
            TAG_INVITE_NONCE,
            TAG_EXPIRY,
            TAG_SIGNATURE,
            TAG_RATCHET_DH,
            TAG_RATCHET_PN,
            TAG_RATCHET_N,
            TAG_CIPHERTEXT,
        ] {
            assert!(!PQ_RESERVED_TAGS.contains(&tag));
        }
    }
}
