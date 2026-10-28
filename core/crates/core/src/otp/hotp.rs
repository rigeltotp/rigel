// SPDX-License-Identifier: GPL-3.0-or-later
//! HOTP, RFC 4226.

use super::{Algorithm, Code, Counter, Digits, OtpError, OtpSecret};

/// Computes the HOTP code for `counter` (RFC 4226, section 5.3).
///
/// The caller increments and stores the counter before it shows the code
/// (V-29); this function does neither.
pub fn hotp(
    secret: &OtpSecret,
    algorithm: Algorithm,
    digits: Digits,
    counter: Counter,
) -> Result<Code, OtpError> {
    let value = super::mac(secret, algorithm, counter.get())?;
    Ok(decimal(value, digits))
}

/// Formats `value mod 10^digits` with leading zeros.
pub(super) fn decimal(value: u32, digits: Digits) -> Code {
    let code = value.checked_rem(digits.modulus()).unwrap_or(0);
    Code::new(format!("{code:0width$}", width = usize::from(digits.get())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC4226_SECRET: &[u8] = b"12345678901234567890";

    fn secret() -> OtpSecret {
        OtpSecret::from_bytes(RFC4226_SECRET.to_vec()).unwrap()
    }

    // RFC 4226, appendix D.
    #[test]
    fn rfc4226_appendix_d() {
        let truncated = [
            1_284_755_224u32,
            1_094_287_082,
            137_359_152,
            1_726_969_429,
            1_640_338_314,
            868_254_676,
            1_918_287_922,
            82_162_583,
            673_399_871,
            645_520_489,
        ];
        let codes = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (count, (&value, &code)) in truncated.iter().zip(codes.iter()).enumerate() {
            let counter = u64::try_from(count).unwrap();
            assert_eq!(
                super::super::mac(&secret(), Algorithm::Sha1, counter),
                Ok(value)
            );
            let got = hotp(
                &secret(),
                Algorithm::Sha1,
                Digits::SIX,
                Counter::new(counter).unwrap(),
            );
            assert_eq!(got.unwrap().as_str(), code, "counter {counter}");
        }
    }

    #[test]
    fn leading_zeros_are_kept() {
        assert_eq!(decimal(82_162_583, Digits::SIX).as_str(), "162583");
        assert_eq!(
            decimal(82_162_583, Digits::new(8).unwrap()).as_str(),
            "82162583"
        );
        assert_eq!(decimal(1_000_000_042, Digits::SIX).as_str(), "000042");
        assert_eq!(decimal(7, Digits::new(7).unwrap()).as_str(), "0000007");
    }

    #[test]
    fn largest_counter_works() {
        let max = Counter::new(Counter::MAX).unwrap();
        assert!(hotp(&secret(), Algorithm::Sha512, Digits::SIX, max).is_ok());
    }
}
