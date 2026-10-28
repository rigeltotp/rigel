// SPDX-License-Identifier: GPL-3.0-or-later
//! HMAC (RFC 2104) over SHA-1, SHA-256 and SHA-512, as used by HOTP and TOTP
//! (RFC 4226, RFC 6238).

use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

/// Hash function of an HMAC. The OTP algorithms of the specs map to these
/// (`docs/specs/vault-format.md`, section 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HmacAlgorithm {
    /// HMAC-SHA-1, the default for TOTP and HOTP. Still secure as a MAC:
    /// collisions in SHA-1 do not break HMAC (threat model, section 7).
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl HmacAlgorithm {
    /// Length of the MAC in bytes.
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Largest MAC any [`HmacAlgorithm`] produces.
const MAX_OUTPUT_LEN: usize = 64;

/// An HMAC value. Zeroed on drop, because for OTP it is one step away from
/// the code. `Debug` is redacted (rule 3).
pub struct HmacOutput {
    buf: Zeroizing<[u8; MAX_OUTPUT_LEN]>,
    len: usize,
}

impl HmacOutput {
    /// The MAC bytes.
    pub fn as_bytes(&self) -> &[u8] {
        // `len` is always one of the `output_len` values, all at most
        // MAX_OUTPUT_LEN, so the range is in bounds; `get` keeps it panic-free.
        self.buf.get(..self.len).unwrap_or_default()
    }

    fn from_slice(mac: &[u8]) -> Self {
        let mut buf = Zeroizing::new([0u8; MAX_OUTPUT_LEN]);
        let len = mac.len().min(MAX_OUTPUT_LEN);
        if let (Some(dst), Some(src)) = (buf.get_mut(..len), mac.get(..len)) {
            dst.copy_from_slice(src);
        }
        Self { buf, len }
    }
}

impl fmt::Debug for HmacOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacOutput(<redacted>)")
    }
}

/// The MAC primitive refused its key. Cannot happen for HMAC, which takes
/// keys of any length (RFC 2104, section 2), but it is reported instead of
/// assumed away.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("MAC key rejected")]
pub struct MacKeyError;

/// Computes `HMAC(key, message)` with the given hash function.
pub fn hmac(
    algorithm: HmacAlgorithm,
    key: &[u8],
    message: &[u8],
) -> Result<HmacOutput, MacKeyError> {
    match algorithm {
        HmacAlgorithm::Sha1 => compute::<Hmac<sha1::Sha1>>(key, message),
        HmacAlgorithm::Sha256 => compute::<Hmac<sha2::Sha256>>(key, message),
        HmacAlgorithm::Sha512 => compute::<Hmac<sha2::Sha512>>(key, message),
    }
}

fn compute<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Result<HmacOutput, MacKeyError> {
    let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| MacKeyError)?;
    mac.update(message);
    Ok(HmacOutput::from_slice(&mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // RFC 4231, test case 2 (key "Jefe").
    #[test]
    fn rfc4231_case2_sha256_and_sha512() {
        let key = b"Jefe";
        let msg = b"what do ya want for nothing?";
        assert_eq!(
            hex(hmac(HmacAlgorithm::Sha256, key, msg).unwrap().as_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(hmac(HmacAlgorithm::Sha512, key, msg).unwrap().as_bytes()),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }

    // RFC 2202, test case 2 (key "Jefe").
    #[test]
    fn rfc2202_case2_sha1() {
        assert_eq!(
            hex(hmac(
                HmacAlgorithm::Sha1,
                b"Jefe",
                b"what do ya want for nothing?"
            )
            .unwrap()
            .as_bytes()),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn output_lengths_match_algorithm() {
        for alg in [
            HmacAlgorithm::Sha1,
            HmacAlgorithm::Sha256,
            HmacAlgorithm::Sha512,
        ] {
            assert_eq!(
                hmac(alg, b"k", b"m").unwrap().as_bytes().len(),
                alg.output_len()
            );
        }
    }

    #[test]
    fn any_key_length_is_accepted() {
        // Keys shorter than, equal to and longer than the hash block size
        // are all accepted (RFC 2104, section 2) and actually used.
        for alg in [
            HmacAlgorithm::Sha1,
            HmacAlgorithm::Sha256,
            HmacAlgorithm::Sha512,
        ] {
            let empty_key = hmac(alg, b"", b"m").unwrap();
            for len in [1usize, 20, 64, 65, 128, 129, 256] {
                let key = vec![0x5a; len];
                assert_ne!(
                    hmac(alg, &key, b"m").unwrap().as_bytes(),
                    empty_key.as_bytes()
                );
            }
        }
    }

    #[test]
    fn debug_is_redacted() {
        let out = hmac(HmacAlgorithm::Sha1, b"k", b"m").unwrap();
        assert_eq!(format!("{out:?}"), "HmacOutput(<redacted>)");
    }
}
