// SPDX-License-Identifier: GPL-3.0-or-later
//! Fuzz target for the otpauth URI parser (`rigel_core::otp::otpauth`).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rigel_core::limits::MAX_LABEL_BYTES;
use rigel_core::otp::{OtpParams, otpauth};

fn check(uri: &str) {
    if let Ok(entry) = otpauth::parse(uri) {
        // Whatever is accepted stays inside the limits of the specs.
        assert!(!(entry.issuer.is_empty() && entry.account.is_empty()));
        assert!(entry.issuer.len() <= MAX_LABEL_BYTES);
        assert!(entry.account.len() <= MAX_LABEL_BYTES);
        assert_eq!(
            entry.counter.is_some(),
            matches!(entry.params, OtpParams::Hotp { .. })
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    check(text);
    // Random bytes rarely start with a valid scheme and type; also feed them
    // behind one, so the label and query parsers get most of the work.
    check(&format!("otpauth://totp/{text}"));
    check(&format!("otpauth://hotp/{text}"));
});
