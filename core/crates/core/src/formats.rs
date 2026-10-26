// SPDX-License-Identifier: GPL-3.0-or-later
//! Format identifiers and current schema versions.
//!
//! The specifications live in `docs/specs/`. Changing a value here requires a
//! spec update, new test files and a migration (CLAUDE.md, rule 7).

/// Vault database format (`docs/specs/vault-format.md`).
pub const VAULT_FORMAT_VERSION: u16 = 1;

/// Schema version of the plaintext entry records inside the vault.
pub const VAULT_RECORD_SCHEMA_VERSION: u16 = 1;

/// Value of the `format` field of a backup payload (`docs/specs/backup-format.md`).
pub const BACKUP_FORMAT_ID: &str = "rigel-backup";

/// Current backup payload schema version.
pub const BACKUP_SCHEMA_VERSION: u16 = 1;

/// Sync protocol version (`docs/specs/sync-format.md`, planned for 1.1).
pub const SYNC_PROTOCOL_VERSION: u16 = 1;

/// Domain-separation prefix for every key derivation and AAD in Rigel.
pub const DOMAIN_PREFIX: &str = "rigel/v1/";

/// Whether this version of Rigel can read a backup with the given schema
/// version (B-10): every version up to the current one, nothing newer.
pub fn is_supported_backup_schema(version: u16) -> bool {
    (1..=BACKUP_SCHEMA_VERSION).contains(&version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_schema_support_follows_b10() {
        assert!(!is_supported_backup_schema(0));
        assert!(is_supported_backup_schema(1));
        assert!(!is_supported_backup_schema(BACKUP_SCHEMA_VERSION + 1));
        assert!(!is_supported_backup_schema(u16::MAX));
    }

    #[test]
    fn identifiers_are_stable() {
        // Changing these needs a spec update and a migration (CLAUDE.md, rule 7).
        assert_eq!(BACKUP_FORMAT_ID, "rigel-backup");
        assert_eq!(DOMAIN_PREFIX, "rigel/v1/");
    }
}
