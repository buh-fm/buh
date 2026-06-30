//! Fuzz invite parsing: arbitrary bytes fed to the verifying invite decoder must never panic.
//! Any input that survives verification (astronomically unlikely from random bytes, but the
//! invariant must hold) must re-encode and re-decode stably.
#![no_main]

use buh_crypto::invite::Invite;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(invite) = Invite::decode(data) {
        let reparsed = Invite::decode(&invite.encode()).expect("re-decode of self-produced invite");
        assert_eq!(invite.nonce, reparsed.nonce);
        assert_eq!(invite.expiry_ms, reparsed.expiry_ms);
    }
    // Also exercise the string entry point on lossy-UTF8 input.
    let _ = Invite::parse(&String::from_utf8_lossy(data));
});
