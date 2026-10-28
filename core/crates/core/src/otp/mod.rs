// SPDX-License-Identifier: GPL-3.0-or-later
//! One-time passwords: HOTP (RFC 4226), TOTP (RFC 6238) and Steam Guard.
//!
//! The UI asks for "the code of entry X" and receives a [`Code`] and the
//! remaining seconds, never the seed (CLAUDE.md, section 1). The current time
//! is passed in by the caller, because this crate has no OS access; the
//! vault decrypts the seed only for the duration of one computation
//! (`docs/specs/vault-format.md`, section 9, step 3).
//!
//! Parameter ranges follow `docs/specs/vault-format.md`, section 6.3, and
//! `docs/specs/backup-format.md`, section 3.2.

mod code;
mod hotp;
mod params;
mod secret;
mod totp;

pub use code::{Code, TimedCode};
pub use hotp::hotp;
pub use params::{Counter, Digits, OtpKind, OtpParams, Period, TimeOffset};
pub use secret::OtpSecret;
pub use totp::{steam, timed_code, totp};

pub use crate::crypto::HmacAlgorithm as Algorithm;

use crate::base32::Base32Error;

/// Why an OTP value could not be built or computed. Carries no secret
/// material, issuer or account (rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OtpError {
    /// The decoded secret is shorter or longer than the limits allow.
    #[error("OTP secret must be 1 to 256 bytes")]
    SecretLength,
    /// The secret is not valid Base32.
    #[error("OTP secret is not valid Base32: {0}")]
    Base32(#[from] Base32Error),
    /// Digits outside 6 to 8.
    #[error("OTP digits must be 6 to 8")]
    Digits,
    /// Period outside 1 to 3600 seconds.
    #[error("OTP period must be 1 to 3600 seconds")]
    Period,
    /// HOTP counter at or above 2^53.
    #[error("HOTP counter out of range")]
    Counter,
    /// Time offset outside −3600 to 3600 seconds.
    #[error("time offset must be -3600 to 3600 seconds")]
    TimeOffset,
    /// The clock plus the time offset is before 1970 or beyond `u64`.
    #[error("time out of range")]
    Time,
    /// A time-based code was requested for a counter-based (HOTP) entry.
    #[error("HOTP entries have no time-based code")]
    NotTimeBased,
    /// The MAC primitive failed (not expected for HMAC).
    #[error("MAC computation failed")]
    Mac,
}

/// The HMAC-based dynamic truncation of RFC 4226, section 5.3: a 31-bit
/// value taken from the MAC at the offset given by its last nibble.
fn dynamic_truncation(mac: &[u8]) -> Result<u32, OtpError> {
    let last = mac.last().ok_or(OtpError::Mac)?;
    let offset = usize::from(last & 0x0f);
    // The largest offset is 15 and the shortest MAC 20 bytes, so the four
    // bytes are always present; `get` keeps a short MAC an error, not a panic.
    let window = offset
        .checked_add(4)
        .and_then(|end| mac.get(offset..end))
        .ok_or(OtpError::Mac)?;
    let bytes: [u8; 4] = window.try_into().map_err(|_| OtpError::Mac)?;
    Ok(u32::from_be_bytes(bytes) & 0x7fff_ffff)
}

fn mac(secret: &OtpSecret, algorithm: Algorithm, moving_factor: u64) -> Result<u32, OtpError> {
    let mac = crate::crypto::hmac(algorithm, secret.expose(), &moving_factor.to_be_bytes())
        .map_err(|_| OtpError::Mac)?;
    dynamic_truncation(mac.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4226_section_5_4_truncation_example() {
        let mac = [
            0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19,
            0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a,
        ];
        assert_eq!(dynamic_truncation(&mac), Ok(0x50ef_7f19));
    }

    #[test]
    fn truncation_rejects_short_macs_without_panicking() {
        assert_eq!(dynamic_truncation(&[]), Err(OtpError::Mac));
        // Offset 15 needs 19 bytes.
        assert_eq!(dynamic_truncation(&[0x0f; 18]), Err(OtpError::Mac));
        assert!(dynamic_truncation(&[0x0f; 19]).is_ok());
    }

    #[test]
    fn errors_contain_no_secret_material() {
        let err = OtpSecret::from_base32("GEZDGNBVGY3TQOJQ1").unwrap_err();
        assert!(!err.to_string().contains("GEZD"));
    }
}
