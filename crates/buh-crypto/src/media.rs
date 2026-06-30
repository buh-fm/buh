//! Per-file content-key media sealing (`doc/design.md` §3.2).
//!
//! Large media never travels through the relay envelope. Instead the sender encrypts the file
//! once under a fresh, single-use **content key**, uploads the opaque ciphertext to a blob node
//! (which holds bytes it cannot read), and folds only the small [`MediaKey`] plus an
//! app-assigned locator into the ratchet envelope. The recipient pulls the ciphertext lazily
//! and opens it with the key from the envelope.
//!
//! The content key is independent of the ratchet: a leaked file key compromises exactly one
//! file and nothing else. Sealing reuses the same XChaCha20-Poly1305 primitive as the envelope
//! ([`crate::aead`]); the 24-byte random nonce is safe to pick per file without birthday
//! concern.

use crate::aead::{self, KEY_LEN, NONCE_LEN};
use crate::error::CryptoError;

/// Domain separator bound as AEAD additional data, so a media ciphertext can never be opened as
/// (or confused with) an envelope ciphertext even under the same key by accident.
const MEDIA_AAD: &[u8] = b"buh-media-v1";

/// Serialized length of a [`MediaKey`]: the content key followed by its nonce.
pub const MEDIA_KEY_LEN: usize = KEY_LEN + NONCE_LEN;

/// A single-use content key for one media file: the symmetric key plus the nonce used to seal
/// it. This is the secret that travels (folded into the ratchet envelope) alongside the blob
/// locator; possession of it — and only it — opens the file.
#[derive(Clone)]
pub struct MediaKey {
    /// XChaCha20-Poly1305 content key.
    pub key: [u8; KEY_LEN],
    /// The nonce the file was sealed under.
    pub nonce: [u8; NONCE_LEN],
}

impl MediaKey {
    /// A fresh content key and nonce from the platform RNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_LEN];
        getrandom::fill(&mut key).expect("system RNG unavailable");
        Self {
            key,
            nonce: aead::random_nonce(),
        }
    }

    /// Serialize as `key ‖ nonce` for folding into a ratchet envelope.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MEDIA_KEY_LEN] {
        let mut out = [0u8; MEDIA_KEY_LEN];
        out[..KEY_LEN].copy_from_slice(&self.key);
        out[KEY_LEN..].copy_from_slice(&self.nonce);
        out
    }

    /// Parse a `key ‖ nonce` blob produced by [`MediaKey::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != MEDIA_KEY_LEN {
            return Err(CryptoError::malformed("media key"));
        }
        let mut key = [0u8; KEY_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        key.copy_from_slice(&bytes[..KEY_LEN]);
        nonce.copy_from_slice(&bytes[KEY_LEN..]);
        Ok(Self { key, nonce })
    }
}

/// Encrypt `plaintext` under a fresh content key. Returns the [`MediaKey`] to fold into the
/// envelope and the opaque ciphertext (ciphertext‖tag) to upload to a blob node.
#[must_use]
pub fn seal_media(plaintext: &[u8]) -> (MediaKey, Vec<u8>) {
    let media_key = MediaKey::generate();
    // seal only fails on an internal AEAD error, which XChaCha20-Poly1305 does not produce for
    // valid key/nonce/inputs; surface it as a panic rather than complicate the happy-path API.
    let ciphertext = aead::seal(&media_key.key, &media_key.nonce, MEDIA_AAD, plaintext)
        .expect("xchacha20-poly1305 seal");
    (media_key, ciphertext)
}

/// Decrypt media `ciphertext` (as returned by [`seal_media`]) under `media_key`. Fails on any
/// key/nonce/tag mismatch without distinguishing the cause.
pub fn open_media(media_key: &MediaKey, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    aead::open(&media_key.key, &media_key.nonce, MEDIA_AAD, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_roundtrips() {
        let plaintext = b"a media file's worth of bytes, sealed once under a per-file key";
        let (key, ciphertext) = seal_media(plaintext);
        assert_ne!(ciphertext, plaintext, "ciphertext is not the plaintext");
        assert_eq!(open_media(&key, &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn media_key_blob_roundtrips() {
        let (key, ciphertext) = seal_media(b"hello");
        let folded = key.to_bytes();
        assert_eq!(folded.len(), MEDIA_KEY_LEN);
        let recovered = MediaKey::from_bytes(&folded).unwrap();
        // The recovered key opens the same ciphertext — this is the envelope round-trip.
        assert_eq!(open_media(&recovered, &ciphertext).unwrap(), b"hello");
    }

    #[test]
    fn fresh_key_and_nonce_each_call() {
        let (a, _) = seal_media(b"x");
        let (b, _) = seal_media(b"x");
        assert_ne!(a.key, b.key, "content keys are single-use");
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (_key, ciphertext) = seal_media(b"secret file");
        let other = MediaKey::generate();
        assert_eq!(
            open_media(&other, &ciphertext),
            Err(CryptoError::Aead),
            "a different content key cannot open the file"
        );
    }

    #[test]
    fn tamper_is_rejected() {
        let (key, mut ciphertext) = seal_media(b"secret file");
        ciphertext[0] ^= 0x01;
        assert_eq!(open_media(&key, &ciphertext), Err(CryptoError::Aead));
    }

    #[test]
    fn short_media_key_blob_errors() {
        assert!(MediaKey::from_bytes(&[0u8; MEDIA_KEY_LEN - 1]).is_err());
        assert!(MediaKey::from_bytes(&[0u8; MEDIA_KEY_LEN + 1]).is_err());
    }
}
