// SPDX-License-Identifier: GPL-3.0-or-later
//! Binding between the native extensions and the Rigel core.
//!
//! Used by the iOS/macOS AutoFill extension (Swift) and the Android Autofill
//! service (Kotlin), generated with UniFFI from E10 on. Launcher widgets do
//! not link this crate: they never show codes.
//!
//! The extension surface is smaller than the app's: it opens the vault
//! read-only, unlocks only through the biometric/device or FIDO2 slot (never
//! the Argon2id password slot, which can exceed the extension memory limit)
//! and returns a code only for entries whose domain or app ID matches.

/// Version of the core, for diagnostics in the extension.
pub fn core_version() -> String {
    rigel_platform::core_version().to_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn reports_core_version() {
        assert_eq!(super::core_version(), rigel_core::VERSION);
    }
}
