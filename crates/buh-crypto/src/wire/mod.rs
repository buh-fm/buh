//! The buh wire codec: a single versioned, tag-length-value framing used by every byte that
//! crosses the boundary — invites, handshake messages, and ratchet envelopes.
//!
//! Everything serialises through here, so this module is built and frozen *first*: its golden
//! bytes and reserved PQ tags are the `doc/design.md` §5.3 contract that lets the PQ-rekey
//! layer be added later without a wire break. See [`v1`] for the frame format.

mod codec;
pub mod v1;

pub use codec::{MAX_VARINT_LEN, Reader, write_varint};
pub use v1::{
    FLAG_HANDSHAKE, FLAG_PQ_REKEY, Field, Frame, PQ_RESERVED_TAGS, TAG_CIPHERTEXT, TAG_EXPIRY,
    TAG_IDENTITY_PUB, TAG_INVITE_NONCE, TAG_PQ_EPOCH, TAG_PQ_KEM_CT, TAG_PREKEY_BUNDLE,
    TAG_QUEUE_URI, TAG_RATCHET_DH, TAG_RATCHET_N, TAG_RATCHET_PN, TAG_SIGNATURE, TAG_SPQR_CHUNK,
};

/// First prelude byte: identifies a buh wire frame.
pub const MAGIC: u8 = 0xB0;

/// Second prelude byte: the wire format version. Bumped only for a true breaking change;
/// additive evolution happens through new TLV tags, not a version bump.
pub const WIRE_VERSION: u8 = 0x01;

/// Errors from decoding or validating a wire frame. All recoverable — the codec never panics.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// First prelude byte was not [`MAGIC`].
    #[error("bad magic byte: 0x{0:02x}")]
    BadMagic(u8),
    /// Wire version is not understood by this build.
    #[error("unsupported wire version: 0x{0:02x}")]
    UnsupportedVersion(u8),
    /// Input ended in the middle of a field or prelude.
    #[error("unexpected end of input")]
    UnexpectedEof,
    /// A varint did not terminate within [`MAX_VARINT_LEN`] bytes or exceeded `u64`.
    #[error("varint overflow")]
    VarintOverflow,
    /// A field length exceeded the platform's `usize`.
    #[error("field length exceeds addressable range")]
    FieldTooLong,
    /// A required field was absent.
    #[error("missing required field with tag 0x{0:02x}")]
    MissingField(u64),
    /// A reserved tag appeared in a context that forbids it (e.g. a PQ tag in a handshake).
    #[error("reserved tag 0x{0:02x} not permitted in this context")]
    ReservedTag(u64),
}
