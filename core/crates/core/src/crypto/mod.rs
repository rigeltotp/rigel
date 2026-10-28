// SPDX-License-Identifier: GPL-3.0-or-later
//! Crypto facade.
//!
//! The only module in Rigel that calls cryptographic primitives (CLAUDE.md,
//! rule 5; `tools/ci/check_policy.py` enforces it). Other modules use the
//! functions and types re-exported here and never name a primitive crate.
//!
//! E3 adds HMAC for one-time passwords. AEAD, KDFs, key agreement,
//! signatures and randomness follow with E4.

mod mac;

pub use mac::{HmacAlgorithm, HmacOutput, MacKeyError, hmac};
