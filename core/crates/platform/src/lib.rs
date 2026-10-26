// SPDX-License-Identifier: GPL-3.0-or-later
//! Rigel platform layer.
//!
//! Everything that needs the operating system: hardware-backed key stores
//! (Secure Enclave, Android Keystore/StrongBox, Windows Hello/TPM via CNG),
//! file access, the SQLite container and FIDO2 security keys over USB/NFC.
//! Linux deliberately has no system-keyring slot (`docs/threat-model.md`).
//!
//! Filled by E4, E5 and E14. `unsafe` is denied by default; OS bindings that
//! need it must allow it locally, with a `// SAFETY:` comment and Miri or
//! platform tests (CLAUDE.md, rule 14).

/// Version of the core this layer was built against.
pub fn core_version() -> &'static str {
    rigel_core::VERSION
}

#[cfg(test)]
mod tests {
    #[test]
    fn links_core() {
        assert_eq!(super::core_version(), rigel_core::VERSION);
    }
}
