// SPDX-License-Identifier: GPL-3.0-or-later
//! Binding between the Flutter app and the Rigel core.
//!
//! The API is generated with flutter_rust_bridge from E6 on. Rules for this
//! surface (CLAUDE.md, section 5): vault and slot keys never cross it; seeds
//! cross it only for typed manual entry (into Rust) and the confirmed
//! plaintext export (out of Rust); QR images and import files come in as raw
//! bytes. The UI asks for "the code of entry X" and receives digits plus the
//! remaining time.

/// Version of the core, for the "About" screen.
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
