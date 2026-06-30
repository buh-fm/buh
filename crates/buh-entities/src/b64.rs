//! Serde helpers for carrying opaque byte payloads as base64 strings in JSON.
//!
//! Envelope payloads are sealed ciphertext — the node never interprets them — so they are
//! transported as standard base64 in JSON request/response bodies.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serializer};

/// Serialize a byte slice as a base64 string.
pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&STANDARD.encode(bytes))
}

/// Deserialize a base64 string into a byte vector.
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    STANDARD
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)
}
