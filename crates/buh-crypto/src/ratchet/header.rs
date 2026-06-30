//! The per-message ratchet header: the sender's current ratchet public key and the two
//! counters a receiver needs to locate the message in the right chain. The header is carried
//! in the clear (the receiver must read it before it can derive the key) but is bound into the
//! AEAD as additional data, so tampering with it makes decryption fail.

use crate::error::CryptoError;
use crate::kem::X25519PublicKey;
use crate::wire::{Frame, TAG_RATCHET_DH, TAG_RATCHET_N, TAG_RATCHET_PN};

/// A Double Ratchet message header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The sender's current ratchet public key.
    pub dh: X25519PublicKey,
    /// Number of messages in the sender's *previous* sending chain.
    pub pn: u32,
    /// Message number within the sender's current sending chain.
    pub n: u32,
}

impl Header {
    /// The canonical header encoding used as AEAD additional-authenticated-data. Deterministic
    /// (fixed field order) so the receiver reconstructs the exact bytes the sender bound.
    #[must_use]
    pub fn to_aad(&self) -> Vec<u8> {
        Frame::new()
            .with_field(TAG_RATCHET_DH, self.dh.to_bytes().to_vec())
            .with_field(TAG_RATCHET_PN, self.pn.to_be_bytes().to_vec())
            .with_field(TAG_RATCHET_N, self.n.to_be_bytes().to_vec())
            .encode()
    }
}

/// Read a big-endian `u32` from exactly four bytes.
pub fn read_u32(bytes: &[u8]) -> Result<u32, CryptoError> {
    let arr: [u8; 4] = bytes
        .try_into()
        .map_err(|_| CryptoError::malformed("ratchet counter"))?;
    Ok(u32::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::X25519SecretKey;

    #[test]
    fn aad_is_deterministic() {
        let dh = X25519SecretKey::generate().public_key();
        let h = Header { dh, pn: 3, n: 7 };
        assert_eq!(h.to_aad(), h.to_aad());
        let h2 = Header { dh, pn: 3, n: 8 };
        assert_ne!(h.to_aad(), h2.to_aad());
    }

    #[test]
    fn read_u32_roundtrip_and_length_check() {
        assert_eq!(read_u32(&42u32.to_be_bytes()).unwrap(), 42);
        assert!(read_u32(&[0, 1, 2]).is_err());
    }
}
