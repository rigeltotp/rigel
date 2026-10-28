// SPDX-License-Identifier: GPL-3.0-or-later
//! The OTP seed.

use core::fmt;

use zeroize::Zeroizing;

use super::OtpError;
use crate::base32;
use crate::limits::{MAX_SECRET_BYTES, MIN_SECRET_BYTES};

/// Longest canonical Base32 seed: [`MAX_SECRET_BYTES`] (256) encode to 410
/// characters (tested below). Longer input is refused before anything is
/// decoded (SR-28).
const MAX_BASE32_CHARS: usize = 410;

/// An OTP seed, 1 to 256 bytes (`docs/specs/vault-format.md`, section 6.3).
///
/// Zeroed on drop; `Debug` is redacted, and there is no `Display` (rules 2
/// and 3). The bytes are readable only inside this crate.
pub struct OtpSecret(Zeroizing<Vec<u8>>);

impl OtpSecret {
    /// Takes ownership of raw seed bytes. They are zeroed even when the
    /// length is rejected.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, OtpError> {
        let bytes = Zeroizing::new(bytes);
        if (MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(OtpError::SecretLength)
        }
    }

    /// Parses the canonical Base32 form used in the vault and in backups
    /// (uppercase, no padding).
    pub fn from_base32(text: &str) -> Result<Self, OtpError> {
        if text.len() > MAX_BASE32_CHARS {
            return Err(OtpError::SecretLength);
        }
        let bytes = base32::decode(text)?;
        if (MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(OtpError::SecretLength)
        }
    }

    /// Length of the seed in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: an empty seed is rejected on construction.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OtpSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpSecret(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_limits() {
        assert_eq!(
            OtpSecret::from_bytes(Vec::new()).unwrap_err(),
            OtpError::SecretLength
        );
        assert_eq!(OtpSecret::from_bytes(vec![1]).unwrap().len(), 1);
        assert_eq!(OtpSecret::from_bytes(vec![1; 256]).unwrap().len(), 256);
        assert_eq!(
            OtpSecret::from_bytes(vec![1; 257]).unwrap_err(),
            OtpError::SecretLength
        );
    }

    #[test]
    fn base32_limits() {
        assert_eq!(
            OtpSecret::from_base32("").unwrap_err(),
            OtpError::SecretLength
        );
        let max = base32::encode(&[0xa5; 256]);
        assert_eq!(max.len(), 410);
        assert_eq!(OtpSecret::from_base32(&max).unwrap().len(), 256);
        let too_long = base32::encode(&[0xa5; 257]);
        assert_eq!(
            OtpSecret::from_base32(&too_long).unwrap_err(),
            OtpError::SecretLength
        );
        // Far too long input is refused before decoding.
        let huge = "A".repeat(1 << 20);
        assert_eq!(
            OtpSecret::from_base32(&huge).unwrap_err(),
            OtpError::SecretLength
        );
    }

    #[test]
    fn base32_is_strict() {
        let lower = OtpSecret::from_base32("gezdgnbvgy3tqojq").unwrap_err();
        assert!(matches!(lower, OtpError::Base32(_)));
        let padded = OtpSecret::from_base32("MZXW6===").unwrap_err();
        assert!(matches!(padded, OtpError::Base32(_)));
    }

    #[test]
    fn debug_is_redacted() {
        let s = OtpSecret::from_base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(format!("{s:?}"), "OtpSecret(<redacted>)");
        assert!(!s.is_empty());
    }
}
