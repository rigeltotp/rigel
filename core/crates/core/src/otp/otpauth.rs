// SPDX-License-Identifier: GPL-3.0-or-later
//! Parser for `otpauth://` URIs ([Key URI format]), as found in QR codes and
//! in plain otpauth lists (`docs/specs/backup-format.md`, section 6.2).
//!
//! The input is hostile (T8, SR-28): its length is checked before anything
//! else, every value is range-checked by the types of [`super::params`], and
//! no input ever causes a panic (fuzz target `otpauth` in `core/fuzz`).
//! Errors carry no part of the input (rule 3).
//!
//! [Key URI format]: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//!
//! Accepted form and leniency:
//!
//! - Scheme `otpauth` and type `totp`, `hotp` or `steam`, case-insensitive.
//!   `totp` with `encoder=steam` is Steam, as Rigel exports it.
//! - Label `issuer:account` or `account`, percent-encoded UTF-8; spaces
//!   around the parts are trimmed. The `issuer` parameter wins over the label
//!   prefix, as in Google Authenticator and Aegis.
//! - Query values are percent-decoded and `+` means a space. Parameter names
//!   are case-insensitive. Unknown parameters (`image`, `icon`, …) are
//!   ignored; a repeated known parameter is rejected, because two readers
//!   could pick different values.
//! - `secret` is Base32 in either case, with optional `=` padding and spaces;
//!   after normalising it must be canonical.
//! - `algorithm` defaults to SHA1, `digits` to 6, `period` to 30; `counter`
//!   is required for HOTP. Steam accepts only its fixed values.
//! - Issuer and account: at most 256 bytes each, not both empty, and no
//!   control or bidirectional-override characters, which could disguise an
//!   issuer in the list.

use core::fmt;

use zeroize::Zeroizing;

use super::{Algorithm, Counter, Digits, OtpError, OtpParams, OtpSecret, Period};
use crate::limits::{MAX_LABEL_BYTES, MAX_OTPAUTH_URI_BYTES};

/// Why an otpauth URI was rejected. Carries no part of the input (rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OtpauthError {
    /// Longer than [`MAX_OTPAUTH_URI_BYTES`].
    #[error("otpauth URI is too long")]
    TooLong,
    /// Not an `otpauth://` URI, or no label or query part.
    #[error("not an otpauth URI")]
    NotOtpauth,
    /// A type other than `totp`, `hotp` or `steam`.
    #[error("unsupported OTP type")]
    UnknownType,
    /// Broken percent-encoding, or text that is not UTF-8.
    #[error("invalid percent-encoding")]
    Encoding,
    /// A query item without `=`.
    #[error("malformed query")]
    MalformedQuery,
    /// A known parameter appears more than once.
    #[error("repeated parameter")]
    DuplicateParameter,
    /// No `secret` parameter.
    #[error("missing secret")]
    MissingSecret,
    /// HOTP without a `counter` parameter.
    #[error("missing HOTP counter")]
    MissingCounter,
    /// Issuer or account too long, both empty, or with forbidden characters.
    #[error("invalid issuer or account name")]
    InvalidName,
    /// An `algorithm` other than SHA1, SHA256 or SHA512.
    #[error("unsupported algorithm")]
    UnknownAlgorithm,
    /// `digits`, `period` or `counter` is not a plain decimal number.
    #[error("invalid number")]
    InvalidNumber,
    /// Steam with an algorithm, digit count or period other than its own.
    #[error("invalid Steam parameters")]
    SteamParameters,
    /// A value outside the ranges of the specs, or an invalid secret.
    #[error(transparent)]
    Otp(#[from] OtpError),
}

/// An entry read from an otpauth URI.
///
/// `Debug` shows only the parameters: names are entry data and the seed is
/// secret (rule 3).
pub struct OtpauthEntry {
    /// Type and parameters.
    pub params: OtpParams,
    /// The seed.
    pub secret: OtpSecret,
    /// The HOTP counter; `None` for time-based entries.
    pub counter: Option<Counter>,
    /// Issuer, possibly empty.
    pub issuer: String,
    /// Account name, possibly empty (but not together with the issuer).
    pub account: String,
}

impl fmt::Debug for OtpauthEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpauthEntry")
            .field("params", &self.params)
            .field("secret", &self.secret)
            .field("counter", &self.counter)
            .field("issuer", &"<redacted>")
            .field("account", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UriType {
    Totp,
    Hotp,
    Steam,
}

/// Raw query values of the known parameters.
#[derive(Default)]
struct Query {
    secret: Option<Zeroizing<String>>,
    issuer: Option<String>,
    algorithm: Option<String>,
    digits: Option<String>,
    period: Option<String>,
    counter: Option<String>,
    encoder: Option<String>,
}

/// Parses one otpauth URI.
pub fn parse(uri: &str) -> Result<OtpauthEntry, OtpauthError> {
    if uri.len() > MAX_OTPAUTH_URI_BYTES {
        return Err(OtpauthError::TooLong);
    }
    let rest = strip_prefix_ignore_case(uri, "otpauth://").ok_or(OtpauthError::NotOtpauth)?;
    let (type_str, rest) = rest.split_once('/').ok_or(OtpauthError::NotOtpauth)?;
    let uri_type = if type_str.eq_ignore_ascii_case("totp") {
        UriType::Totp
    } else if type_str.eq_ignore_ascii_case("hotp") {
        UriType::Hotp
    } else if type_str.eq_ignore_ascii_case("steam") {
        UriType::Steam
    } else {
        return Err(OtpauthError::UnknownType);
    };
    // A fragment carries nothing for us.
    let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
    let (label, query) = rest.split_once('?').ok_or(OtpauthError::NotOtpauth)?;

    let label =
        String::from_utf8(percent_decode(label, false)?).map_err(|_| OtpauthError::Encoding)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (Some(issuer.trim()), account.trim()),
        None => (None, label.trim()),
    };

    let query = parse_query(query)?;
    let issuer = match (&query.issuer, label_issuer) {
        (Some(param), _) => param.trim(),
        (None, Some(prefix)) => prefix,
        (None, None) => "",
    };
    check_names(issuer, account)?;

    let secret = query.secret.as_deref().ok_or(OtpauthError::MissingSecret)?;
    let secret = OtpSecret::from_base32(&normalise_base32(secret))?;

    let algorithm = match query.algorithm.as_deref() {
        None => Algorithm::Sha1,
        Some(a) if a.eq_ignore_ascii_case("SHA1") => Algorithm::Sha1,
        Some(a) if a.eq_ignore_ascii_case("SHA256") => Algorithm::Sha256,
        Some(a) if a.eq_ignore_ascii_case("SHA512") => Algorithm::Sha512,
        Some(_) => return Err(OtpauthError::UnknownAlgorithm),
    };
    let digits = query.digits.as_deref().map(parse_number).transpose()?;
    let period = query.period.as_deref().map(parse_number).transpose()?;
    let is_steam = uri_type == UriType::Steam
        || (uri_type == UriType::Totp
            && query
                .encoder
                .as_deref()
                .is_some_and(|e| e.eq_ignore_ascii_case("steam")));

    let (params, counter) = if is_steam {
        let steam_like = algorithm == Algorithm::Sha1
            && digits.is_none_or(|d| d == 5)
            && period.is_none_or(|p| p == 30);
        if !steam_like {
            return Err(OtpauthError::SteamParameters);
        }
        (OtpParams::Steam, None)
    } else {
        let digits = match digits {
            None => Digits::SIX,
            Some(d) => Digits::new(u8::try_from(d).map_err(|_| OtpError::Digits)?)?,
        };
        if uri_type == UriType::Hotp {
            let counter = query
                .counter
                .as_deref()
                .ok_or(OtpauthError::MissingCounter)?;
            let counter = Counter::new(parse_number(counter)?)?;
            (OtpParams::Hotp { algorithm, digits }, Some(counter))
        } else {
            let period = match period {
                None => Period::THIRTY_S,
                Some(p) => Period::new(u32::try_from(p).map_err(|_| OtpError::Period)?)?,
            };
            (
                OtpParams::Totp {
                    algorithm,
                    digits,
                    period,
                },
                None,
            )
        }
    };

    Ok(OtpauthEntry {
        params,
        secret,
        counter,
        issuer: issuer.to_owned(),
        account: account.to_owned(),
    })
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        s.get(prefix.len()..)
    } else {
        None
    }
}

fn parse_query(query: &str) -> Result<Query, OtpauthError> {
    let mut q = Query::default();
    for item in query.split('&').filter(|item| !item.is_empty()) {
        let (key, raw) = item.split_once('=').ok_or(OtpauthError::MalformedQuery)?;
        let key = key.to_ascii_lowercase();
        if key == "secret" {
            // Decoded straight into a zeroizing buffer; `from_utf8` reuses it.
            let bytes = Zeroizing::new(percent_decode(raw, true)?);
            let text = core::str::from_utf8(&bytes).map_err(|_| OtpauthError::Encoding)?;
            set_once(&mut q.secret, Zeroizing::new(text.to_owned()))?;
            continue;
        }
        let slot = match key.as_str() {
            "issuer" => &mut q.issuer,
            "algorithm" => &mut q.algorithm,
            "digits" => &mut q.digits,
            "period" => &mut q.period,
            "counter" => &mut q.counter,
            "encoder" => &mut q.encoder,
            // Unknown parameters are ignored, but must still be well-formed.
            _ => {
                percent_decode(raw, true)?;
                continue;
            }
        };
        let value =
            String::from_utf8(percent_decode(raw, true)?).map_err(|_| OtpauthError::Encoding)?;
        set_once(slot, value)?;
    }
    Ok(q)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), OtpauthError> {
    if slot.is_some() {
        return Err(OtpauthError::DuplicateParameter);
    }
    *slot = Some(value);
    Ok(())
}

/// Decodes `%XX` escapes; with `plus_is_space`, `+` becomes a space (query
/// values, as in HTML forms). The output is never longer than the input.
fn percent_decode(s: &str, plus_is_space: bool) -> Result<Vec<u8>, OtpauthError> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let hi = bytes
                    .next()
                    .and_then(hex_value)
                    .ok_or(OtpauthError::Encoding)?;
                let lo = bytes
                    .next()
                    .and_then(hex_value)
                    .ok_or(OtpauthError::Encoding)?;
                out.push((hi << 4) | lo);
            }
            b'+' if plus_is_space => out.push(b' '),
            _ => out.push(b),
        }
    }
    Ok(out)
}

fn hex_value(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|v| u8::try_from(v).ok())
}

/// A plain decimal number: ASCII digits only (no sign, no spaces), at most
/// 20 of them, fitting `u64`.
fn parse_number(s: &str) -> Result<u64, OtpauthError> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(OtpauthError::InvalidNumber);
    }
    s.parse().map_err(|_| OtpauthError::InvalidNumber)
}

/// Uppercase, without spaces and `=` padding: the canonical form that
/// [`OtpSecret::from_base32`] accepts.
fn normalise_base32(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len()));
    let trimmed = s.trim_end_matches(['=', ' ']);
    out.extend(
        trimmed
            .chars()
            .filter(|&c| c != ' ')
            .map(|c| c.to_ascii_uppercase()),
    );
    out
}

fn check_names(issuer: &str, account: &str) -> Result<(), OtpauthError> {
    if issuer.is_empty() && account.is_empty() {
        return Err(OtpauthError::InvalidName);
    }
    for name in [issuer, account] {
        if name.len() > MAX_LABEL_BYTES || name.chars().any(is_forbidden_in_name) {
            return Err(OtpauthError::InvalidName);
        }
    }
    Ok(())
}

/// Control characters and the Unicode bidirectional controls (embeddings,
/// overrides, isolates and marks), which can make one issuer look like
/// another.
fn is_forbidden_in_name(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otp::{OtpKind, TimeOffset, hotp, timed_code};
    use proptest::prelude::*;

    // RFC 6238 seed "12345678901234567890" in Base32 (the only seed used in
    // tests, CLAUDE.md rule 18).
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn ok(uri: &str) -> OtpauthEntry {
        parse(uri).unwrap()
    }

    fn err(uri: &str) -> OtpauthError {
        parse(uri).unwrap_err()
    }

    #[test]
    fn spec_examples() {
        // docs/specs/backup-format.md, section 6.2.
        let totp = ok(&format!(
            "otpauth://totp/Example:alice%40example.com?secret={SEED}&issuer=Example&algorithm=SHA1&digits=6&period=30"
        ));
        assert_eq!(totp.issuer, "Example");
        assert_eq!(totp.account, "alice@example.com");
        assert_eq!(
            totp.params,
            OtpParams::Totp {
                algorithm: Algorithm::Sha1,
                digits: Digits::SIX,
                period: Period::THIRTY_S
            }
        );
        assert_eq!(totp.counter, None);
        let code = timed_code(&totp.secret, &totp.params, 59, TimeOffset::ZERO).unwrap();
        assert_eq!(code.code().as_str(), "287082");

        let hotp_entry = ok(&format!(
            "otpauth://hotp/Example:bob?secret={SEED}&issuer=Example&counter=0"
        ));
        assert_eq!(hotp_entry.params.kind(), OtpKind::Hotp);
        assert_eq!(hotp_entry.counter, Some(Counter::new(0).unwrap()));
        let code = hotp(
            &hotp_entry.secret,
            Algorithm::Sha1,
            Digits::SIX,
            Counter::new(0).unwrap(),
        )
        .unwrap();
        assert_eq!(code.as_str(), "755224");

        let steam = ok(&format!(
            "otpauth://totp/Steam:gabe?secret={SEED}&issuer=Steam&digits=5&period=30&encoder=steam"
        ));
        assert_eq!(steam.params, OtpParams::Steam);
    }

    #[test]
    fn defaults_and_minimal_form() {
        let e = ok(&format!("otpauth://totp/alice?secret={SEED}"));
        assert_eq!(e.issuer, "");
        assert_eq!(e.account, "alice");
        assert_eq!(
            e.params,
            OtpParams::Totp {
                algorithm: Algorithm::Sha1,
                digits: Digits::SIX,
                period: Period::THIRTY_S
            }
        );
    }

    #[test]
    fn all_parameters() {
        let e = ok(&format!(
            "otpauth://totp/A?secret={SEED}&algorithm=sha512&digits=8&period=60"
        ));
        assert_eq!(
            e.params,
            OtpParams::Totp {
                algorithm: Algorithm::Sha512,
                digits: Digits::new(8).unwrap(),
                period: Period::new(60).unwrap()
            }
        );
        let e = ok(&format!(
            "otpauth://hotp/A?secret={SEED}&algorithm=SHA256&digits=7&counter=9007199254740991"
        ));
        assert_eq!(e.params.algorithm(), Algorithm::Sha256);
        assert_eq!(e.counter.map(Counter::get), Some(Counter::MAX));
    }

    #[test]
    fn case_insensitive_scheme_type_and_keys() {
        let e = ok(&format!("OTPAUTH://TOTP/A?SECRET={SEED}&Digits=7"));
        assert_eq!(e.params.kind(), OtpKind::Totp);
        let OtpParams::Totp { digits, .. } = e.params else {
            panic!()
        };
        assert_eq!(digits.get(), 7);
    }

    #[test]
    fn steam_forms() {
        assert_eq!(
            ok(&format!("otpauth://steam/gabe?secret={SEED}")).params,
            OtpParams::Steam
        );
        assert_eq!(
            ok(&format!("otpauth://totp/gabe?secret={SEED}&encoder=Steam")).params,
            OtpParams::Steam
        );
        // `encoder` only matters for totp.
        assert_eq!(
            ok(&format!(
                "otpauth://hotp/gabe?secret={SEED}&counter=1&encoder=steam"
            ))
            .params
            .kind(),
            OtpKind::Hotp
        );
        for bad in ["&digits=6", "&period=60", "&algorithm=SHA256"] {
            assert_eq!(
                err(&format!("otpauth://steam/gabe?secret={SEED}{bad}")),
                OtpauthError::SteamParameters
            );
        }
    }

    #[test]
    fn label_forms() {
        let e = ok(&format!(
            "otpauth://totp/ACME%20Co:%20john.doe%40email.com?secret={SEED}"
        ));
        assert_eq!(e.issuer, "ACME Co");
        assert_eq!(e.account, "john.doe@email.com");
        // Encoded colon, and an issuer parameter that wins over the prefix.
        let e = ok(&format!(
            "otpauth://totp/Old%3Ajohn?secret={SEED}&issuer=New+Name"
        ));
        assert_eq!(e.issuer, "New Name");
        assert_eq!(e.account, "john");
        // Only the first colon separates; '+' stays literal in the label.
        let e = ok(&format!("otpauth://totp/a:b:c+d?secret={SEED}"));
        assert_eq!(e.issuer, "a");
        assert_eq!(e.account, "b:c+d");
        // Issuer without account, and UTF-8.
        let e = ok(&format!("otpauth://totp/%C3%84rzte:?secret={SEED}"));
        assert_eq!(e.issuer, "Ärzte");
        assert_eq!(e.account, "");
        let e = ok(&format!("otpauth://totp/?secret={SEED}&issuer=OnlyIssuer"));
        assert_eq!(e.issuer, "OnlyIssuer");
    }

    #[test]
    fn lenient_secret_forms() {
        for secret in [
            "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
            "GEZD%20GNBV%20GY3T%20QOJQ%20GEZD%20GNBV%20GY3T%20QOJQ",
            "GEZD+GNBV+GY3T+QOJQ+GEZD+GNBV+GY3T+QOJQ",
        ] {
            let e = ok(&format!("otpauth://totp/A?secret={secret}"));
            let code = timed_code(&e.secret, &e.params, 59, TimeOffset::ZERO).unwrap();
            assert_eq!(code.code().as_str(), "287082");
        }
        // "MZXW6" is "foo": padding is accepted, a wrong trailing bit is not.
        assert!(parse("otpauth://totp/A?secret=MZXW6%3D%3D%3D").is_ok());
        assert!(parse("otpauth://totp/A?secret=mzxw6===").is_ok());
        assert!(matches!(
            err("otpauth://totp/A?secret=MZXW7"),
            OtpauthError::Otp(OtpError::Base32(_))
        ));
    }

    #[test]
    fn rejects_structural_errors() {
        assert_eq!(err(""), OtpauthError::NotOtpauth);
        assert_eq!(err("http://totp/A?secret=MZXW6"), OtpauthError::NotOtpauth);
        assert_eq!(err("otpauth://totp"), OtpauthError::NotOtpauth);
        assert_eq!(err("otpauth://totp/A"), OtpauthError::NotOtpauth);
        assert_eq!(
            err("otpauth://motp/A?secret=MZXW6"),
            OtpauthError::UnknownType
        );
        assert_eq!(err("otpauth://totp/A?secret"), OtpauthError::MalformedQuery);
        assert_eq!(
            err("otpauth://totp/A?issuer=x"),
            OtpauthError::MissingSecret
        );
        assert_eq!(
            err("otpauth://hotp/A?secret=MZXW6"),
            OtpauthError::MissingCounter
        );
        assert_eq!(
            err("otpauth://totp/A?secret=MZXW6&secret=MZXW6"),
            OtpauthError::DuplicateParameter
        );
        assert_eq!(
            err("otpauth://totp/A?secret=MZXW6&Digits=6&digits=6"),
            OtpauthError::DuplicateParameter
        );
        assert_eq!(
            err("otpauth://totp/A?secret=MZXW6&algorithm=MD5"),
            OtpauthError::UnknownAlgorithm
        );
        // Multi-byte input where the prefix would end inside a character.
        assert_eq!(err("otpauth:/ä"), OtpauthError::NotOtpauth);
    }

    #[test]
    fn rejects_bad_encoding() {
        for uri in [
            "otpauth://totp/A%?secret=MZXW6",
            "otpauth://totp/A%4?secret=MZXW6",
            "otpauth://totp/A%G0?secret=MZXW6",
            "otpauth://totp/%FF?secret=MZXW6",
            "otpauth://totp/A?secret=MZXW6&issuer=%C3",
            "otpauth://totp/A?secret=%FF",
            "otpauth://totp/A?secret=MZXW6&image=%Z1",
        ] {
            assert_eq!(err(uri), OtpauthError::Encoding, "{uri}");
        }
    }

    #[test]
    fn ignores_unknown_parameters_and_fragment() {
        let e = ok(&format!(
            "otpauth://totp/A?secret={SEED}&image=https%3A%2F%2Fexample.com%2Fx.png&&color=red#frag"
        ));
        assert_eq!(e.account, "A");
    }

    #[test]
    fn number_rules() {
        for bad in [
            "",
            "+6",
            "-6",
            " 6",
            "6 ",
            "0x6",
            "６",
            "123456789012345678901",
        ] {
            assert_eq!(
                err(&format!("otpauth://totp/A?secret={SEED}&digits={bad}")),
                OtpauthError::InvalidNumber,
                "{bad:?}"
            );
        }
        assert_eq!(
            err(&format!(
                "otpauth://totp/A?secret={SEED}&digits=99999999999"
            )),
            OtpauthError::Otp(OtpError::Digits)
        );
        assert_eq!(
            err(&format!("otpauth://totp/A?secret={SEED}&digits=5")),
            OtpauthError::Otp(OtpError::Digits)
        );
        assert_eq!(
            err(&format!("otpauth://totp/A?secret={SEED}&period=0")),
            OtpauthError::Otp(OtpError::Period)
        );
        assert_eq!(
            err(&format!("otpauth://totp/A?secret={SEED}&period=4294967296")),
            OtpauthError::Otp(OtpError::Period)
        );
        assert_eq!(
            err(&format!(
                "otpauth://hotp/A?secret={SEED}&counter=9007199254740992"
            )),
            OtpauthError::Otp(OtpError::Counter)
        );
        assert_eq!(
            err(&format!(
                "otpauth://hotp/A?secret={SEED}&counter=18446744073709551616"
            )),
            OtpauthError::InvalidNumber
        );
    }

    #[test]
    fn name_rules() {
        assert_eq!(
            err(&format!("otpauth://totp/?secret={SEED}")),
            OtpauthError::InvalidName
        );
        assert_eq!(
            err(&format!("otpauth://totp/%20:%20?secret={SEED}")),
            OtpauthError::InvalidName
        );
        let long = "a".repeat(MAX_LABEL_BYTES + 1);
        assert_eq!(
            err(&format!("otpauth://totp/{long}?secret={SEED}")),
            OtpauthError::InvalidName
        );
        assert!(parse(&format!("otpauth://totp/{}?secret={SEED}", &long[1..])).is_ok());
        assert_eq!(
            err(&format!("otpauth://totp/A?secret={SEED}&issuer={long}")),
            OtpauthError::InvalidName
        );
        for bad in [
            "%00",
            "%0A",
            "%7F",
            "%C2%85",
            "%E2%80%AE",
            "%E2%81%A6",
            "%E2%80%8F",
        ] {
            assert_eq!(
                err(&format!("otpauth://totp/Ba{bad}nk:x?secret={SEED}")),
                OtpauthError::InvalidName,
                "{bad}"
            );
        }
    }

    #[test]
    fn secret_limits() {
        assert_eq!(
            err("otpauth://totp/A?secret="),
            OtpauthError::Otp(OtpError::SecretLength)
        );
        let max = crate::base32::encode(&[0x42; 256]);
        assert!(parse(&format!("otpauth://totp/A?secret={}", max.as_str())).is_ok());
        let too_long = crate::base32::encode(&[0x42; 257]);
        assert_eq!(
            err(&format!("otpauth://totp/A?secret={}", too_long.as_str())),
            OtpauthError::Otp(OtpError::SecretLength)
        );
    }

    #[test]
    fn length_limit_is_checked_first() {
        let pad = "x".repeat(MAX_OTPAUTH_URI_BYTES);
        assert_eq!(
            err(&format!("otpauth://totp/A?secret={SEED}&image={pad}")),
            OtpauthError::TooLong
        );
        let prefix = format!("otpauth://totp/A?secret={SEED}&image=");
        let exact = format!(
            "{prefix}{}",
            "x".repeat(MAX_OTPAUTH_URI_BYTES - prefix.len())
        );
        assert_eq!(exact.len(), MAX_OTPAUTH_URI_BYTES);
        assert!(parse(&exact).is_ok());
    }

    #[test]
    fn debug_hides_names_and_seed() {
        let e = ok(&format!("otpauth://totp/MyBank:alice?secret={SEED}"));
        let debug = format!("{e:?}");
        assert!(!debug.contains("MyBank") && !debug.contains("alice") && !debug.contains("GEZD"));
    }

    #[test]
    fn errors_contain_no_input() {
        let msg = err("otpauth://totp/MyBank:alice?secret=MZXW6&algorithm=SECRETALG").to_string();
        assert!(!msg.contains("MyBank") && !msg.contains("SECRETALG"));
    }

    fn encode_component(s: &str) -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    proptest! {
        #[test]
        fn never_panics(s in "\\PC{0,200}") {
            let _ = parse(&s);
        }

        #[test]
        fn never_panics_on_otpauth_like_input(s in "otpauth://(totp|hotp|steam|x)/[%A-Za-z0-9:+=&?#é ]{0,120}") {
            let _ = parse(&s);
        }

        // Every valid entry written as a URI parses back to the same values.
        #[test]
        fn roundtrip(
            issuer in "[^:\\p{Cc}\\u{200E}\\u{200F}\\u{202A}-\\u{202E}\\u{2066}-\\u{2069}\\u{061C}]{0,20}",
            account in "[^\\p{Cc}\\u{200E}\\u{200F}\\u{202A}-\\u{202E}\\u{2066}-\\u{2069}\\u{061C}]{1,20}",
            seed in proptest::collection::vec(any::<u8>(), 1..=64),
            kind in 0u8..3,
            alg in 0u8..3,
            digits in 6u8..=8,
            period in 1u32..=3600,
            counter in 0u64..=Counter::MAX,
        ) {
            let issuer = issuer.trim().to_owned();
            let account = account.trim().to_owned();
            prop_assume!(!account.is_empty());
            let alg_name = ["SHA1", "SHA256", "SHA512"][usize::from(alg)];
            let secret = crate::base32::encode(&seed);
            let label = format!("{}:{}", encode_component(&issuer), encode_component(&account));
            let common = format!("secret={}&issuer={}", secret.as_str(), encode_component(&issuer));
            let uri = match kind {
                0 => format!("otpauth://totp/{label}?{common}&algorithm={alg_name}&digits={digits}&period={period}"),
                1 => format!("otpauth://hotp/{label}?{common}&algorithm={alg_name}&digits={digits}&counter={counter}"),
                _ => format!("otpauth://totp/{label}?{common}&digits=5&period=30&encoder=steam"),
            };
            let e = parse(&uri).unwrap();
            prop_assert_eq!(&e.issuer, &issuer);
            prop_assert_eq!(&e.account, &account);
            prop_assert_eq!(e.secret.expose(), seed.as_slice());
            match kind {
                0 => {
                    prop_assert_eq!(e.params.kind(), OtpKind::Totp);
                    prop_assert_eq!(e.params.period().map(Period::get), Some(period));
                }
                1 => {
                    prop_assert_eq!(e.params.kind(), OtpKind::Hotp);
                    prop_assert_eq!(e.counter.map(Counter::get), Some(counter));
                }
                _ => prop_assert_eq!(e.params, OtpParams::Steam),
            }
        }
    }
}
