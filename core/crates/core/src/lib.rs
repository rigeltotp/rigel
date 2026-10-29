// SPDX-License-Identifier: GPL-3.0-or-later
//! Rigel core.
//!
//! Pure logic without any I/O or operating-system access. Everything that
//! touches OTP seeds or keys lives here. Planned modules (see `docs/`):
//!
//! - `otp`: HOTP (RFC 4226), TOTP (RFC 6238), Steam Guard, otpauth parser (E3)
//! - `base32`: canonical Base32 for OTP secrets and recovery codes (E3)
//! - `qr`: QR image input in Rust: camera frames, PNG, JPEG (E3)
//! - `crypto`: the only place that calls cryptographic primitives (HMAC in
//!   E3, the rest in E4)
//! - `vault`: key hierarchy, unlock slots, encrypted records (E4)
//! - `backup`: age-based backups (E8)
//! - `import`: importers for other authenticator apps (E9)
//! - `sync`: folder sync protocol (1.1, E12)
//!
//! Modules are added by their epics; this crate must stay free of `unsafe`,
//! network code and platform APIs.

#![forbid(unsafe_code)]

pub mod base32;
pub mod crypto;
pub mod formats;
pub mod limits;
pub mod otp;
pub mod qr;

/// Version of this crate, as shown in "About" and written into backups.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
