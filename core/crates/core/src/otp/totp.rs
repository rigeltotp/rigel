// SPDX-License-Identifier: GPL-3.0-or-later
//! TOTP (RFC 6238) and Steam Guard.

use super::hotp::decimal;
use super::{
    Algorithm, Code, Digits, OtpError, OtpParams, OtpSecret, Period, TimeOffset, TimedCode,
};

/// Steam Guard alphabet: digits and consonants without look-alikes.
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";
const STEAM_CHARS: usize = 5;

/// The time step `T` of RFC 6238, section 4.2, with `T0 = 0`, and the
/// seconds until the next step.
///
/// `now_unix_s` is the device clock in seconds since 1970-01-01 UTC. It is a
/// `u64`, so nothing changes in 2038 or 2106.
fn time_step(now_unix_s: u64, offset: TimeOffset, period: Period) -> Result<(u64, u32), OtpError> {
    let t = now_unix_s
        .checked_add_signed(i64::from(offset.get()))
        .ok_or(OtpError::Time)?;
    let period_s = u64::from(period.get());
    let step = t.checked_div(period_s).ok_or(OtpError::Period)?;
    let into_step = t.checked_rem(period_s).ok_or(OtpError::Period)?;
    // `into_step < period_s <= 3600`, so the difference is 1 to 3600.
    let remaining = period_s
        .checked_sub(into_step)
        .and_then(|r| u32::try_from(r).ok())
        .ok_or(OtpError::Period)?;
    Ok((step, remaining))
}

/// Computes the TOTP code at `now_unix_s`, corrected by the entry's
/// `offset` (RFC 6238, section 4).
pub fn totp(
    secret: &OtpSecret,
    algorithm: Algorithm,
    digits: Digits,
    period: Period,
    now_unix_s: u64,
    offset: TimeOffset,
) -> Result<TimedCode, OtpError> {
    let (step, remaining_s) = time_step(now_unix_s, offset, period)?;
    let value = super::mac(secret, algorithm, step)?;
    Ok(TimedCode {
        code: decimal(value, digits),
        remaining_s,
        period_s: period.get(),
    })
}

/// Computes the Steam Guard code at `now_unix_s`: TOTP with HMAC-SHA-1 and
/// 30 s, with the truncated value written in base 26 over the Steam
/// alphabet, least significant character first.
pub fn steam(
    secret: &OtpSecret,
    now_unix_s: u64,
    offset: TimeOffset,
) -> Result<TimedCode, OtpError> {
    let period = Period::THIRTY_S;
    let (step, remaining_s) = time_step(now_unix_s, offset, period)?;
    let mut value = super::mac(secret, Algorithm::Sha1, step)?;
    let mut text = String::with_capacity(STEAM_CHARS);
    for _ in 0..STEAM_CHARS {
        let index = value.checked_rem(26).ok_or(OtpError::Mac)?;
        let c = usize::try_from(index)
            .ok()
            .and_then(|i| STEAM_ALPHABET.get(i))
            .ok_or(OtpError::Mac)?;
        text.push(char::from(*c));
        value = value.checked_div(26).ok_or(OtpError::Mac)?;
    }
    Ok(TimedCode {
        code: Code::new(text),
        remaining_s,
        period_s: period.get(),
    })
}

/// Computes the current code of a time-based entry. HOTP entries are
/// rejected: their code depends on the stored counter, see [`super::hotp`].
pub fn timed_code(
    secret: &OtpSecret,
    params: &OtpParams,
    now_unix_s: u64,
    offset: TimeOffset,
) -> Result<TimedCode, OtpError> {
    match *params {
        OtpParams::Totp {
            algorithm,
            digits,
            period,
        } => totp(secret, algorithm, digits, period, now_unix_s, offset),
        OtpParams::Steam => steam(secret, now_unix_s, offset),
        OtpParams::Hotp { .. } => Err(OtpError::NotTimeBased),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{Counter, hotp};
    use proptest::prelude::*;

    // RFC 6238, appendix B: the seed is "1234567890" repeated to the hash
    // output length.
    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    fn secret(seed: &[u8]) -> OtpSecret {
        OtpSecret::from_bytes(seed.to_vec()).unwrap()
    }

    fn code_at(
        seed: &[u8],
        algorithm: Algorithm,
        digits: u8,
        period: u32,
        now: u64,
        offset: i32,
    ) -> String {
        totp(
            &secret(seed),
            algorithm,
            Digits::new(digits).unwrap(),
            Period::new(period).unwrap(),
            now,
            TimeOffset::new(offset).unwrap(),
        )
        .unwrap()
        .code()
        .as_str()
        .to_owned()
    }

    #[test]
    fn rfc6238_appendix_b() {
        let vectors: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for &(t, sha1, sha256, sha512) in vectors {
            assert_eq!(
                code_at(SEED_SHA1, Algorithm::Sha1, 8, 30, t, 0),
                sha1,
                "SHA1 at {t}"
            );
            assert_eq!(
                code_at(SEED_SHA256, Algorithm::Sha256, 8, 30, t, 0),
                sha256,
                "SHA256 at {t}"
            );
            assert_eq!(
                code_at(SEED_SHA512, Algorithm::Sha512, 8, 30, t, 0),
                sha512,
                "SHA512 at {t}"
            );
        }
    }

    // Reference values computed with Python's `hmac` module, independently of
    // this implementation.
    #[test]
    fn year_2038_and_2106() {
        for (t, code) in [
            (2_147_483_647u64, "703886"),
            (2_147_483_648, "703886"),
            (4_294_967_295, "791428"),
            (4_294_967_296, "791428"),
        ] {
            assert_eq!(
                code_at(SEED_SHA1, Algorithm::Sha1, 6, 30, t, 0),
                code,
                "at {t}"
            );
        }
        // 2^31 is inside the step that started at 2147483640.
        let timed = timed_code(
            &secret(SEED_SHA1),
            &sha1_30(),
            2_147_483_648,
            TimeOffset::ZERO,
        )
        .unwrap();
        assert_eq!(timed.remaining_s(), 22);
    }

    fn sha1_30() -> OtpParams {
        OtpParams::Totp {
            algorithm: Algorithm::Sha1,
            digits: Digits::SIX,
            period: Period::THIRTY_S,
        }
    }

    #[test]
    fn step_boundaries_and_remaining_time() {
        let s = secret(SEED_SHA1);
        let at = |t| timed_code(&s, &sha1_30(), t, TimeOffset::ZERO).unwrap();
        assert_eq!(at(0).code().as_str(), "755224");
        assert_eq!(at(0).remaining_s(), 30);
        assert_eq!(at(29).code().as_str(), "755224");
        assert_eq!(at(29).remaining_s(), 1);
        assert_eq!(at(30).code().as_str(), "287082");
        assert_eq!(at(30).remaining_s(), 30);
        assert_eq!(at(30).period_s(), 30);
    }

    #[test]
    fn period_change_moves_the_step_boundary() {
        // With 60 s, t = 30..59 still belongs to step 0.
        assert_eq!(code_at(SEED_SHA1, Algorithm::Sha1, 6, 60, 59, 0), "755224");
        assert_eq!(code_at(SEED_SHA1, Algorithm::Sha1, 6, 60, 60, 0), "287082");
        assert_eq!(code_at(SEED_SHA1, Algorithm::Sha1, 6, 30, 59, 0), "287082");
        // A period of 1 s makes every second a new step; 3600 s one per hour.
        assert_eq!(code_at(SEED_SHA1, Algorithm::Sha1, 6, 1, 1, 0), "287082");
        assert_eq!(
            code_at(SEED_SHA1, Algorithm::Sha1, 6, 3600, 3599, 0),
            "755224"
        );
        assert_eq!(
            code_at(SEED_SHA1, Algorithm::Sha1, 6, 3600, 3600, 0),
            "287082"
        );
    }

    #[test]
    fn time_offset_shifts_the_clock() {
        // A clock 10 s behind with +10 s gives the code of t = 30.
        assert_eq!(code_at(SEED_SHA1, Algorithm::Sha1, 6, 30, 20, 10), "287082");
        assert_eq!(
            code_at(SEED_SHA1, Algorithm::Sha1, 6, 30, 3630, -3600),
            "287082"
        );
        assert_eq!(
            code_at(SEED_SHA1, Algorithm::Sha1, 6, 30, 0, 3600),
            code_at(SEED_SHA1, Algorithm::Sha1, 6, 30, 3600, 0)
        );
    }

    #[test]
    fn time_out_of_range_is_an_error_not_a_panic() {
        let s = secret(SEED_SHA1);
        let back = TimeOffset::new(-1).unwrap();
        assert_eq!(timed_code(&s, &sha1_30(), 0, back), Err(OtpError::Time));
        let ahead = TimeOffset::new(1).unwrap();
        assert_eq!(
            timed_code(&s, &sha1_30(), u64::MAX, ahead),
            Err(OtpError::Time)
        );
        assert!(timed_code(&s, &sha1_30(), u64::MAX, TimeOffset::ZERO).is_ok());
        assert_eq!(steam(&s, 0, back), Err(OtpError::Time));
    }

    // Reference values from the algorithm of the `steam` Python package
    // (`steam.guard.generate_twofactor_code_for_time`), run with Python's
    // `hmac` module on the RFC 6238 seed.
    #[test]
    fn steam_reference_values() {
        let s = secret(SEED_SHA1);
        for (t, code) in [
            (59u64, "PV9M4"),
            (1_111_111_109, "PY4YB"),
            (1_234_567_890, "VHHQY"),
            (2_000_000_000, "9N776"),
            (2_147_483_647, "866PD"),
            (2_147_483_648, "866PD"),
            (4_294_967_296, "BRCMF"),
            (20_000_000_000, "R5DMB"),
        ] {
            let timed = timed_code(&s, &OtpParams::Steam, t, TimeOffset::ZERO).unwrap();
            assert_eq!(timed.code().as_str(), code, "at {t}");
            assert_eq!(timed.period_s(), 30);
        }
    }

    #[test]
    fn hotp_entries_have_no_timed_code() {
        let params = OtpParams::Hotp {
            algorithm: Algorithm::Sha1,
            digits: Digits::SIX,
        };
        assert_eq!(
            timed_code(&secret(SEED_SHA1), &params, 59, TimeOffset::ZERO),
            Err(OtpError::NotTimeBased)
        );
    }

    proptest! {
        // TOTP is HOTP over the time step (RFC 6238, section 4.2).
        #[test]
        fn totp_is_hotp_of_the_time_step(
            seed in proptest::collection::vec(any::<u8>(), 1..=64),
            now in any::<u64>(),
            period in 1u32..=3600,
            offset in -3600i32..=3600,
            digits in 6u8..=8,
        ) {
            let s = OtpSecret::from_bytes(seed).unwrap();
            let digits = Digits::new(digits).unwrap();
            let period = Period::new(period).unwrap();
            let offset = TimeOffset::new(offset).unwrap();
            match now.checked_add_signed(i64::from(offset.get())) {
                None => prop_assert_eq!(
                    totp(&s, Algorithm::Sha256, digits, period, now, offset),
                    Err(OtpError::Time)
                ),
                Some(t) => {
                    let timed = totp(&s, Algorithm::Sha256, digits, period, now, offset).unwrap();
                    let step = t.checked_div(u64::from(period.get())).unwrap();
                    if let Ok(counter) = Counter::new(step) {
                        let expected = hotp(&s, Algorithm::Sha256, digits, counter).unwrap();
                        prop_assert_eq!(timed.code(), &expected);
                    }
                    prop_assert_eq!(timed.code().as_str().len(), usize::from(digits.get()));
                    prop_assert!(timed.code().as_str().bytes().all(|b| b.is_ascii_digit()));
                    prop_assert!((1..=period.get()).contains(&timed.remaining_s()));
                }
            }
        }

        #[test]
        fn steam_codes_use_the_steam_alphabet(seed in proptest::collection::vec(any::<u8>(), 1..=64), now in any::<u64>()) {
            let s = OtpSecret::from_bytes(seed).unwrap();
            let timed = steam(&s, now, TimeOffset::ZERO).unwrap();
            prop_assert_eq!(timed.code().as_str().len(), STEAM_CHARS);
            prop_assert!(timed.code().as_str().bytes().all(|b| STEAM_ALPHABET.contains(&b)));
        }
    }
}
