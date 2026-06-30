//! Fuzz the TLV wire decoder: arbitrary bytes must never panic or over-allocate, and any
//! frame that decodes must re-encode identically (decode is the inverse of encode on its
//! image). This guards the `doc/design.md` §5.3 wire contract and the "decryptMessage never
//! panics" property.
#![no_main]

use buh_crypto::wire::Frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = Frame::decode(data) {
        // Round-trip stability: a decoded frame must re-encode to bytes that decode equal.
        let reencoded = frame.encode();
        let again = Frame::decode(&reencoded).expect("re-decode of self-produced bytes");
        assert_eq!(frame, again);
    }
});
