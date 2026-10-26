# Backup and export format

Status: Draft 1 (2026-10-25), for review. Backup schema version 1.
Implemented by: `rigel-core` (`backup`, `import`). Epics: E8, E9, E17.

Backups must outlive the app. Rigel therefore uses the open
[age](https://age-encryption.org/v1) format instead of a format of its own:
anyone can decrypt a Rigel backup with the `age` or `rage` command-line tool
and read the JSON inside, even if Rigel no longer exists.

```sh
age -d backup.rigel.age > backup.json     # asks for the backup passphrase
```

## 1. File types

| File | Content | Protection |
| ---- | ------- | ---------- |
| `*.rigel.age` | encrypted backup: age file containing the backup payload (section 3) | passphrase (scrypt) |
| `*.rigel.json` | plaintext export: the same payload, unencrypted | none, behind unlock and warning |
| `*.txt` | plaintext export: one otpauth URI per line (section 6.2) | none, behind unlock and warning |
| `*.pdf` | paper backup: one QR code per entry (section 6.3) | none, behind unlock and warning |

## 2. Encrypted container

- B-1: An encrypted backup is an age v1 file (`age-encryption.org/v1`),
  binary (not ASCII-armored). Readers also accept the armored form. The file
  name ends in `.rigel.age`.
- B-2: Writers use exactly one recipient stanza, of type `scrypt`
  (passphrase), as age requires for passphrase files.
- B-3: The passphrase must pass the minimum strength of the app password
  (vault-format.md, V-23). The app offers a generated passphrase of 5 words.
- B-4: Writers choose the scrypt work factor `log2(N)` for about 1 s on the
  device, never below 18. Readers refuse work factors above 22 before
  deriving anything (via the age library's maximum work factor), to bound
  the cost a hostile file can impose.
- B-5: Password backups are fully symmetric (scrypt and ChaCha20-Poly1305
  with a 128-bit file key, as defined by age) and therefore not exposed to
  "harvest now, decrypt later" attacks on public-key cryptography. A 128-bit
  file key corresponds to NIST post-quantum security category 1 (like
  AES-128); in practice the passphrase is the weaker part.
- B-6: **Hybrid post-quantum recipient, deferred.** The plan foresees an
  optional public-key recipient with X25519 + ML-KEM-768 for a separate
  backup key. Status checked on 2026-10-25: `rage` 0.12.1 (the Rust age
  library) implements only the encryption-only, tagged `mlkem768p256tag`
  recipient for hardware keys, and not the native hybrid
  `mlkem768x25519` identity type with decryption. Rigel 1.0 therefore
  writes passphrase backups only. Readers MUST refuse files with other
  stanza types with a clear message, not with a generic error. Support is
  added (with a schema-compatible change, no payload change) once `rage`
  supports a hybrid native identity; see open point 1.

## 3. Payload

The payload is a JSON object (RFC 8259, UTF-8 without BOM), followed by one
line feed and then ASCII spaces.

- B-7: Writers pad the payload with spaces to a multiple of 4096 bytes, so
  the file size reveals the number of entries only coarsely. Readers accept
  any amount of trailing whitespace.
- B-8: The machine-readable schema is
  [`../schemas/backup-v1.schema.json`](../schemas/backup-v1.schema.json).
  Where this text and the schema disagree, this text wins and the schema is
  fixed.

```json
{
  "format": "rigel-backup",
  "schema_version": 1,
  "created_at": "2026-10-25T20:15:00Z",
  "app": { "name": "Rigel", "version": "1.0.0" },
  "source_vault_id": "5f0c6f1e-3a52-4c1e-9a43-2a8f0f9f4b10",
  "entries": [
    {
      "id": "0b8b2d55-2f0a-4e2c-a8d9-6a8f6d1f7e01",
      "type": "totp",
      "issuer": "Example",
      "account": "alice@example.com",
      "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
      "algorithm": "SHA1",
      "digits": 6,
      "period": 30,
      "time_offset_s": 0,
      "websites": ["example.com"],
      "apps": [{ "platform": "android", "id": "com.example.app" }],
      "tags": ["work"],
      "favorite": false,
      "sort_key": "a0",
      "icon": { "source": "builtin", "id": "example" },
      "note": "",
      "created_at": "2026-10-25T20:15:00Z",
      "updated_at": "2026-10-25T20:15:00Z"
    }
  ],
  "settings": { "hide_codes": false }
}
```

### 3.1 Top level

| Member | Required | Content |
| ------ | -------- | ------- |
| `format` | yes | the string `rigel-backup` |
| `schema_version` | yes | integer, `1` for this spec |
| `created_at` | yes | RFC 3339 UTC |
| `app` | yes | `{ "name": string, "version": string }` of the writer |
| `source_vault_id` | no | UUID of the vault the backup came from; used by the restore test |
| `entries` | yes | array of entries (section 3.2), at most 10,000 |
| `settings` | no | portable settings (section 3.3) |

### 3.2 Entries

Entries carry the same information as a vault entry (vault-format.md,
section 6), flattened, without per-field HLC times.

| Member | Required | Content |
| ------ | -------- | ------- |
| `id` | yes | UUID of the entry (kept on restore) |
| `type` | yes | `totp`, `hotp` or `steam` |
| `issuer`, `account` | yes | strings, at most 256 bytes each, not both empty |
| `secret` | yes | Base32 (RFC 4648, uppercase, no padding), 1 to 256 bytes decoded |
| `algorithm` | yes | `SHA1`, `SHA256` or `SHA512` |
| `digits` | yes | 6 to 8; `steam`: 5 |
| `period` | for `totp`, `steam` | seconds, 1 to 3600; `steam`: 30 |
| `counter` | for `hotp` | integer, 0 to 2^53 − 1 |
| `time_offset_s` | no | integer, −3600 to 3600, default 0 |
| `websites` | no | array of domains, as in the vault |
| `apps` | no | array of app references, as in the vault |
| `tags` | no | array of strings |
| `favorite` | no | boolean, default `false` |
| `sort_key` | no | fractional index string |
| `icon` | no | icon reference or `null` |
| `note` | no | string, at most 4096 bytes |
| `created_at`, `updated_at` | no | RFC 3339 UTC |

Tombstones (deleted entries) are never written to backups.

### 3.3 Settings

Only portable, non-secret preferences: `hide_codes`, `clipboard_clear_s`,
`sort_mode`, `theme`. Device-bound data (slots, lock state, HLC node ID,
automatic-backup folder and credential) is never part of a backup.

### 3.4 Compatibility rules

- B-9: Readers refuse `format` values other than `rigel-backup`.
- B-10: Readers accept every `schema_version` up to the newest they know
  and refuse newer ones with "this backup needs a newer Rigel".
- B-11: Readers ignore unknown members. A future schema version adds members
  rather than changing the meaning of existing ones.
- B-12: Every schema version has test files in `docs/formats/backup/v<N>/`
  that are never changed or deleted. Rigel's tests decrypt and import all of
  them (README in that directory).

## 4. Restore and import

- B-13: Import never writes before the user has seen a preview: number of
  entries, new ones, duplicates and conflicts.
- B-14: Duplicate detection: same `id` → same entry (identical or
  conflicting); otherwise same `type` and decoded `secret` and same
  `issuer`/`account` → likely duplicate. The user chooses per group: skip,
  import as copy, or replace.
- B-15: Restore into an empty vault keeps `id`, `sort_key`, tags and
  favourites. Restore never changes slots, the app password or the recovery
  code.
- B-16: **Restore test.** The app can decrypt a backup and compare it with
  the vault without writing anything: entries missing from the backup,
  entries only in the backup, and entries that differ. The result is shown;
  nothing is stored except the date of the last successful test.

## 5. Automatic backups

- B-20: Off by default. Turning them on requires choosing a folder and a
  separate backup passphrase (strength-checked, B-3). The passphrase is
  stored in the vault as the backup credential record (vault-format.md,
  section 7.2), so backups run without asking, and a backup can be restored
  with the passphrase alone, without the vault.
- B-21: A backup is written after changes (debounced, at most once per
  10 minutes) and at most once a day otherwise; never while locked if that
  would require the password.
- B-22: Files are named `rigel-backup-YYYYMMDD-HHMMSSZ.rigel.age`, written to
  a temporary name in the same folder and renamed when complete. The app
  keeps the newest N files (default 10) and deletes only files it wrote that
  match this pattern.
- B-23: A failed backup is shown in the app; failures are never silent.
- B-24: Folder access uses the platform's user-granted mechanism (Storage
  Access Framework on Android, security-scoped bookmarks on Apple
  platforms). The folder can be synced by any service the user chooses;
  Rigel itself does no networking.

## 6. Plaintext exports

- B-30: Plaintext exports require a fresh unlock, an explicit warning that
  the file gives full access to all accounts, and a second confirmation.
  They are never written automatically.
- B-31: Seeds leave Rust only for these exports (CLAUDE.md, rule 1). The
  file content is produced in Rust and handed to the UI as bytes for saving.

### 6.1 JSON

The backup payload of section 3, unpadded, as `*.rigel.json`. Decrypting a
`*.rigel.age` backup with the `age` tool yields a file that Rigel imports
the same way.

### 6.2 otpauth list

One URI per line, in the [Key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format):

```
otpauth://totp/Example:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=6&period=30
otpauth://hotp/Example:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&counter=0
```

Steam entries are written as `otpauth://totp/…&digits=5&period=30&encoder=steam`.
Fields that the URI format cannot carry (tags, websites, notes, icons) are
lost; the app says so before the export.

### 6.3 Paper backup

A PDF with, per entry, a QR code of the otpauth URI and the issuer, account
and Base32 secret as text, and a warning on every page. It is generated in
Rust (no platform print service receives the seed before the user chooses
to print).

### 6.4 Aegis format (release 1.2)

Specified in E17. Encrypted with a password like an Aegis backup.

## 7. Importers (E9)

Importers parse the export formats of: Google Authenticator (migration QR
codes, protobuf), Aegis (plain and encrypted), Raivo, 2FAS, Ente Auth,
Bitwarden, andOTP, FreeOTP, FreeOTP+, Authy and Microsoft Authenticator (app
data only, on Android with root, as Aegis does), WinAuth, TOTP Authenticator,
Authenticator Plus, and plain otpauth lists. Each importer gets its own
section in this spec with its source format version, a fuzz target and
test files made from fake seeds only.

## 8. Limits

Every parser of backups, exports and imports checks these limits before it
allocates (SR-28). They are mirrored in `core/crates/core/src/limits.rs`.

| Limit | Value |
| ----- | ----- |
| File size (backup, export or import file) | 16 MiB |
| QR image size | 20 MiB |
| Entries per file | 10,000 |
| otpauth URI length | 4096 bytes |
| Decoded secret | 1 to 256 bytes |
| Issuer, account | 256 bytes each |
| Note | 4096 bytes |
| Tags, websites, apps per entry | 64 each |
| JSON nesting depth | 16 |
| scrypt work factor accepted | log2(N) ≤ 22 |

Inputs above a limit are refused as a whole with a clear message; nothing
is truncated silently.

## 9. Open points for review

1. Hybrid post-quantum backup recipient (B-6): wait for `rage`, or define a
   Rigel-specific age plugin. Recommendation: wait; password backups are
   already quantum-resistant.
2. Whether the paper backup should optionally be encrypted (QR code of an
   age file), at the cost of needing a passphrase on paper too.

## Changelog

- Draft 1 (2026-10-25): first version.
