// SPDX-License-Identifier: GPL-3.0-or-later
//! Validated OTP parameters. Each type can only hold values the specs allow
//! (`docs/specs/vault-format.md`, section 6.3), so code generation never sees
//! an out-of-range value.

use super::{Algorithm, OtpError};

/// The OTP type, as named in the specs (`otp.type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OtpKind {
    /// Time-based, RFC 6238.
    Totp,
    /// Counter-based, RFC 4226.
    Hotp,
    /// Steam Guard: TOTP with HMAC-SHA-1, 30 s and five characters of the
    /// Steam alphabet.
    Steam,
}

impl OtpKind {
    /// The name used in the vault, in backups and in otpauth URIs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
            Self::Steam => "steam",
        }
    }
}

/// Number of decimal digits of a TOTP or HOTP code: 6 to 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Digits(u8);

impl Digits {
    /// Six digits, the common default.
    pub const SIX: Self = Self(6);

    /// Validates a digit count.
    pub const fn new(digits: u8) -> Result<Self, OtpError> {
        match digits {
            6..=8 => Ok(Self(digits)),
            _ => Err(OtpError::Digits),
        }
    }

    /// The digit count.
    pub const fn get(self) -> u8 {
        self.0
    }

    /// `10^digits`, the modulus of RFC 4226, section 5.3.
    pub(crate) const fn modulus(self) -> u32 {
        match self.0 {
            6 => 1_000_000,
            7 => 10_000_000,
            _ => 100_000_000,
        }
    }
}

/// Length of a TOTP time step in seconds: 1 to 3600.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Period(u32);

impl Period {
    /// 30 seconds, the RFC 6238 default and the only Steam period.
    pub const THIRTY_S: Self = Self(30);

    /// Validates a period.
    pub const fn new(seconds: u32) -> Result<Self, OtpError> {
        match seconds {
            1..=3600 => Ok(Self(seconds)),
            _ => Err(OtpError::Period),
        }
    }

    /// The period in seconds.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Per-entry clock correction in seconds, −3600 to 3600, added to the
/// device clock (`time_offset_s`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TimeOffset(i32);

impl TimeOffset {
    /// No correction.
    pub const ZERO: Self = Self(0);

    /// Validates an offset.
    pub const fn new(seconds: i32) -> Result<Self, OtpError> {
        match seconds {
            -3600..=3600 => Ok(Self(seconds)),
            _ => Err(OtpError::TimeOffset),
        }
    }

    /// The offset in seconds.
    pub const fn get(self) -> i32 {
        self.0
    }
}

/// HOTP moving factor, below 2^53 so that it survives JSON number handling
/// in backups (`docs/specs/backup-format.md`, section 3.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Counter(u64);

impl Counter {
    /// Largest allowed counter, 2^53 − 1.
    pub const MAX: u64 = (1 << 53) - 1;

    /// Validates a counter.
    pub const fn new(value: u64) -> Result<Self, OtpError> {
        if value <= Self::MAX {
            Ok(Self(value))
        } else {
            Err(OtpError::Counter)
        }
    }

    /// The counter value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The following counter. The vault stores it before it shows the code
    /// (V-29); at the maximum this fails instead of wrapping, because a
    /// repeated counter would repeat codes.
    pub const fn next(self) -> Result<Self, OtpError> {
        match self.0.checked_add(1) {
            Some(v) => Self::new(v),
            None => Err(OtpError::Counter),
        }
    }
}

/// Everything about an entry's OTP except the seed and the HOTP counter
/// (the `otp` value of V-28 without `secret`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OtpParams {
    /// Time-based code.
    Totp {
        /// Hash function.
        algorithm: Algorithm,
        /// Code length.
        digits: Digits,
        /// Time step.
        period: Period,
    },
    /// Counter-based code; the counter is stored separately (V-29).
    Hotp {
        /// Hash function.
        algorithm: Algorithm,
        /// Code length.
        digits: Digits,
    },
    /// Steam Guard; all parameters are fixed.
    Steam,
}

impl OtpParams {
    /// The type of this entry.
    pub const fn kind(&self) -> OtpKind {
        match self {
            Self::Totp { .. } => OtpKind::Totp,
            Self::Hotp { .. } => OtpKind::Hotp,
            Self::Steam => OtpKind::Steam,
        }
    }

    /// The hash function (`SHA1` for Steam).
    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Totp { algorithm, .. } | Self::Hotp { algorithm, .. } => *algorithm,
            Self::Steam => Algorithm::Sha1,
        }
    }

    /// The time step, `None` for HOTP.
    pub const fn period(&self) -> Option<Period> {
        match self {
            Self::Totp { period, .. } => Some(*period),
            Self::Steam => Some(Period::THIRTY_S),
            Self::Hotp { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_range() {
        assert_eq!(Digits::new(5), Err(OtpError::Digits));
        for d in 6..=8 {
            assert_eq!(Digits::new(d).unwrap().get(), d);
        }
        assert_eq!(Digits::new(9), Err(OtpError::Digits));
        assert_eq!(Digits::new(0), Err(OtpError::Digits));
        assert_eq!(Digits::new(u8::MAX), Err(OtpError::Digits));
        assert_eq!(Digits::new(7).unwrap().modulus(), 10_000_000);
    }

    #[test]
    fn period_range() {
        assert_eq!(Period::new(0), Err(OtpError::Period));
        assert_eq!(Period::new(1).unwrap().get(), 1);
        assert_eq!(Period::new(3600).unwrap().get(), 3600);
        assert_eq!(Period::new(3601), Err(OtpError::Period));
        assert_eq!(Period::new(u32::MAX), Err(OtpError::Period));
    }

    #[test]
    fn time_offset_range() {
        assert_eq!(TimeOffset::new(-3601), Err(OtpError::TimeOffset));
        assert_eq!(TimeOffset::new(-3600).unwrap().get(), -3600);
        assert_eq!(TimeOffset::new(3600).unwrap().get(), 3600);
        assert_eq!(TimeOffset::new(3601), Err(OtpError::TimeOffset));
        assert_eq!(TimeOffset::new(i32::MIN), Err(OtpError::TimeOffset));
        assert_eq!(TimeOffset::default(), TimeOffset::ZERO);
    }

    #[test]
    fn counter_range_and_next() {
        assert_eq!(Counter::new(Counter::MAX).unwrap().get(), (1 << 53) - 1);
        assert_eq!(Counter::new(Counter::MAX + 1), Err(OtpError::Counter));
        assert_eq!(Counter::new(u64::MAX), Err(OtpError::Counter));
        assert_eq!(Counter::new(41).unwrap().next().unwrap().get(), 42);
        assert_eq!(
            Counter::new(Counter::MAX).unwrap().next(),
            Err(OtpError::Counter)
        );
    }

    #[test]
    fn params_accessors() {
        let steam = OtpParams::Steam;
        assert_eq!(steam.kind(), OtpKind::Steam);
        assert_eq!(steam.algorithm(), Algorithm::Sha1);
        assert_eq!(steam.period(), Some(Period::THIRTY_S));
        let hotp = OtpParams::Hotp {
            algorithm: Algorithm::Sha256,
            digits: Digits::SIX,
        };
        assert_eq!(hotp.kind(), OtpKind::Hotp);
        assert_eq!(hotp.algorithm(), Algorithm::Sha256);
        assert_eq!(hotp.period(), None);
        let totp = OtpParams::Totp {
            algorithm: Algorithm::Sha512,
            digits: Digits::SIX,
            period: Period::new(60).unwrap(),
        };
        assert_eq!(totp.kind(), OtpKind::Totp);
        assert_eq!(totp.period().map(Period::get), Some(60));
        assert_eq!(
            [OtpKind::Totp, OtpKind::Hotp, OtpKind::Steam].map(OtpKind::as_str),
            ["totp", "hotp", "steam"]
        );
    }
}
