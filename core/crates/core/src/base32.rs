// SPDX-License-Identifier: GPL-3.0-or-later
//! Base32 (RFC 4648, section 6) in the canonical form of the specs:
//! uppercase alphabet, no padding (`docs/specs/vault-format.md`, section 2).
//!
//! Used for OTP secrets, so decoded bytes and encoded text are returned in
//! [`Zeroizing`] containers, and errors never contain input characters.

use zeroize::Zeroizing;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Why a Base32 string was rejected. Carries no part of the input (rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Base32Error {
    /// A character outside the uppercase RFC 4648 alphabet, including `=`.
    #[error("invalid Base32 character")]
    InvalidCharacter,
    /// A length that no byte string encodes to (1, 3 or 6 modulo 8).
    #[error("invalid Base32 length")]
    InvalidLength,
    /// The unused bits of the last character are not zero, so the string is
    /// not the canonical encoding of any byte string.
    #[error("non-canonical Base32 trailing bits")]
    NonCanonical,
}

fn value(c: u8) -> Option<u64> {
    let index = ALPHABET.iter().position(|&a| a == c)?;
    u64::try_from(index).ok()
}

/// Decodes canonical Base32. The caller limits the input length first
/// (SR-28); the output is shorter than the input.
///
/// Works in blocks of eight characters (40 bits, five bytes). A short last
/// block is filled with zero bits; those, and the unused bits of its last
/// character, must be zero in the result (canonical form).
pub fn decode(input: &str) -> Result<Zeroizing<Vec<u8>>, Base32Error> {
    let mut out = Zeroizing::new(Vec::with_capacity(input.len()));
    for chunk in input.as_bytes().chunks(8) {
        // Bytes 3..8 of the big-endian block hold the 40 bits.
        let used = match chunk.len() {
            2 => 3..4,
            4 => 3..5,
            5 => 3..6,
            7 => 3..7,
            8 => 3..8,
            _ => return Err(Base32Error::InvalidLength),
        };
        let mut block: u64 = 0;
        for i in 0..8 {
            let v = match chunk.get(i) {
                Some(&c) => value(c).ok_or(Base32Error::InvalidCharacter)?,
                None => 0,
            };
            block = (block << 5) | v;
        }
        let bytes = Zeroizing::new(block.to_be_bytes());
        let tail = bytes.get(used.end..).unwrap_or_default();
        if tail.iter().any(|&b| b != 0) {
            return Err(Base32Error::NonCanonical);
        }
        out.extend_from_slice(bytes.get(used).unwrap_or_default());
    }
    Ok(out)
}

/// Encodes bytes as canonical Base32.
pub fn encode(data: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(data.len().saturating_mul(2)));
    for chunk in data.chunks(5) {
        // Characters for this many bytes, and where the bytes go in the block.
        let (chars, used) = match chunk.len() {
            1 => (2, 3..4),
            2 => (4, 3..5),
            3 => (5, 3..6),
            4 => (7, 3..7),
            _ => (8, 3..8),
        };
        let mut bytes = Zeroizing::new([0u8; 8]);
        if let Some(dst) = bytes.get_mut(used) {
            dst.copy_from_slice(chunk);
        }
        let mut block = u64::from_be_bytes(*bytes);
        for _ in 0..chars {
            // The top five of the 40 bits, masked, always index the alphabet.
            let index = usize::try_from((block >> 35) & 0x1f).unwrap_or_default();
            if let Some(&c) = ALPHABET.get(index) {
                out.push(char::from(c));
            }
            block <<= 5;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // RFC 4648, section 10, with the padding removed.
    const RFC4648: &[(&str, &str)] = &[
        ("", ""),
        ("f", "MY"),
        ("fo", "MZXQ"),
        ("foo", "MZXW6"),
        ("foob", "MZXW6YQ"),
        ("fooba", "MZXW6YTB"),
        ("foobar", "MZXW6YTBOI"),
    ];

    #[test]
    fn rfc4648_vectors() {
        for &(plain, encoded) in RFC4648 {
            assert_eq!(encode(plain.as_bytes()).as_str(), encoded);
            assert_eq!(decode(encoded).unwrap().as_slice(), plain.as_bytes());
        }
    }

    #[test]
    fn rfc6238_seed() {
        assert_eq!(
            encode(b"12345678901234567890").as_str(),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
    }

    #[test]
    fn rejects_non_canonical_forms() {
        assert_eq!(decode("my"), Err(Base32Error::InvalidCharacter));
        assert_eq!(decode("MY======"), Err(Base32Error::InvalidCharacter));
        assert_eq!(decode("MZ XQ"), Err(Base32Error::InvalidCharacter));
        assert_eq!(decode("MZXW1"), Err(Base32Error::InvalidCharacter));
        assert_eq!(decode("M"), Err(Base32Error::InvalidLength));
        assert_eq!(decode("MZX"), Err(Base32Error::InvalidLength));
        assert_eq!(decode("MZXW6Y"), Err(Base32Error::InvalidLength));
        // "MZ" leaves two non-zero trailing bits; "MY" is the canonical "f".
        assert_eq!(decode("MZ"), Err(Base32Error::NonCanonical));
    }

    #[test]
    fn error_messages_contain_no_input() {
        let msg = decode("Q1QQQQQQ").unwrap_err().to_string();
        assert!(!msg.contains('Q') && !msg.contains('1'));
    }

    proptest! {
        #[test]
        fn roundtrip(data in proptest::collection::vec(any::<u8>(), 0..300)) {
            let encoded = encode(&data);
            let decoded = decode(&encoded).unwrap();
            prop_assert_eq!(decoded.as_slice(), data.as_slice());
        }

        // Whatever decodes is the one canonical encoding of its bytes.
        #[test]
        fn accepted_input_is_canonical(s in "[A-Z2-7]{0,80}") {
            if let Ok(bytes) = decode(&s) {
                let encoded = encode(&bytes);
                prop_assert_eq!(encoded.as_str(), s.as_str());
            }
        }

        #[test]
        fn arbitrary_input_never_panics(s in "\\PC{0,80}") {
            let _ = decode(&s);
        }
    }
}
