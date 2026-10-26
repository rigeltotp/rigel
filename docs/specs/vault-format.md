# Vault format

Status: Draft 1 (2026-10-25), for review. Format version 1.
Implemented by: `rigel-core` (`crypto`, `vault`), `rigel-platform` (SQLite,
key stores). Epics: E4, E5, E14.

The vault is the local, encrypted store of all entries on one device. This
spec defines the key hierarchy, the unlock slots, how records are encrypted,
and the SQLite container. It already contains every field needed up to
release 1.2 (AutoFill, sync, icon packs), so those releases need no vault
migration.

## 1. Overview

```
 app password ──Argon2id──┐
 recovery code ──HKDF─────┤
 device key (SE/Keystore/ ├──► KEK ──XChaCha20-Poly1305──► wrapped vault key (one per slot)
   TPM) ──ECDH/HKDF───────┤                                   │ unwrap with any slot
 FIDO2 hmac-secret/PRF ───┘                                   ▼
                                                        vault key VK (256 bit, random)
                                                              │ HKDF-SHA-256, per purpose
                       ┌──────────────────┬───────────────────┼────────────────────┐
                       ▼                  ▼                   ▼                    ▼
                    K_meta            K_secret            K_settings          K_backup_cred
               entry metadata      OTP secrets          app settings        auto-backup key
               (issuer, account,   (seed, algorithm,
                domains, tags…)     digits, counter…)
```

- V-1: The vault key `VK` is 32 random bytes from the OS CSPRNG, created once
  per vault. It is never stored in plaintext and never leaves `rigel-core`.
- V-2: `VK` is stored only wrapped, once per unlock slot. Any single valid
  slot unwraps it. Adding, removing or changing a slot never re-encrypts
  records.
- V-3: Every entry consists of two records encrypted separately: a
  **meta** record (shown in the list) and a **secret** record (decrypted only
  to compute a code or for a confirmed export).
- V-4: There is no unencrypted vault mode, ever.

## 2. Primitives and encodings

| Purpose | Primitive | Crate (planned) |
| ------- | --------- | --------------- |
| AEAD | XChaCha20-Poly1305, 24-byte random nonce, 16-byte tag | `chacha20poly1305` |
| Password KDF | Argon2id, version 0x13 (RFC 9106) | `argon2` |
| Key derivation | HKDF-SHA-256 (RFC 5869) | `hkdf`, `sha2` |
| Hash | SHA-256 | `sha2` |
| Random | OS CSPRNG (`getrandom`) | `getrandom` / `rand_core` |
| Device slot on Apple | ECDH P-256 in the Secure Enclave | Security.framework |

- V-5: Only the `crypto` module of `rigel-core` calls these primitives
  (CLAUDE.md, rule 5).
- V-6: Nonces are always 24 random bytes. A nonce is never derived, counted
  or reused. With random 192-bit nonces, collisions are negligible for any
  realistic number of encryptions under one key.

Encodings:

- **UUID**: 16 bytes, RFC 9562 version 4 (random). In JSON: lowercase
  hyphenated string.
- **Base64**: RFC 4648 standard alphabet with padding, used for binary
  values inside JSON that are not OTP secrets.
- **Base32**: RFC 4648 alphabet, uppercase, no padding, used for OTP
  secrets (the common format of otpauth URIs).
- **Timestamps** for humans: RFC 3339 in UTC with `Z`, seconds precision.
- **Hybrid logical clock (HLC)**, used for per-field change times (section
  6.4): the string `MMMMMMMMMMMM-CCCC-NNNNNNNNNNNNNNNN` with 12 lowercase hex
  digits of Unix time in milliseconds, 4 hex digits of logical counter and
  16 hex digits of node ID (a random 64-bit ID of this vault instance).
  Comparing two HLC strings byte-wise gives their total order.
- **Text** is UTF-8. Passwords and recovery input are normalised to Unicode
  NFC before use, so the same password works on every platform.

## 3. Key derivation from the vault key

- V-7: Purpose keys are derived as

  ```
  K_purpose = HKDF-SHA-256(IKM = VK, salt = vault_id, info = "rigel/v1/key/" || purpose, L = 32)
  ```

  with `purpose` one of:

  | Purpose | Used for |
  | ------- | -------- |
  | `entry-meta` | meta records (kind 1) |
  | `entry-secret` | secret records (kind 2) |
  | `settings` | settings record (kind 3) |
  | `backup-credential` | automatic-backup credential (kind 4) |
  | `sync-state` | sync state record (kind 5, release 1.1) |
  | `device-identity` | sync device identity (kind 6, release 1.1) |

- V-8: Purpose keys are derived when the vault is unlocked, held in
  `zeroize`-on-drop types, and dropped with `VK` when the vault locks.

## 4. Unlock slots

### 4.1 Common slot structure

Each slot has a 16-byte random `slot_id`, a `slot_type`, a `slot_version`
(currently 1), a `params` document (JSON, non-secret, needed before unlock)
and a `wrapped_key`.

- V-10: The slot's key-encryption key `KEK` (32 bytes) is derived per slot
  type (sections 4.2 to 4.5). `VK` is wrapped as an envelope (section 5.1)
  with key `KEK` and this AAD:

  ```
  AAD_slot = "rigel/v1/slot" || 0x00 || vault_id (16) || slot_id (16)
             || slot_type (u8) || slot_version (u16) || SHA-256(params bytes as stored)
  ```

  Binding the params hash means tampering with salts or KDF parameters makes
  the unwrap fail instead of silently weakening the slot.
- V-11: Before running any KDF or contacting any device, the reader checks
  the params against the bounds of the slot type and refuses out-of-range
  values. This bounds the work a tampered file can force.
- V-12: A failed unwrap gives one generic error ("wrong password or damaged
  slot") and never reveals which check failed.
- V-13: Slot types:

  | `slot_type` | Name | Count per vault | Since |
  | ----------- | ---- | --------------- | ----- |
  | 1 | password | exactly 1 in 1.0 (see V-26) | 1.0 |
  | 2 | recovery | exactly 1 | 1.0 |
  | 3 | device (biometric) | 0 or 1 per device | 1.0 |
  | 4 | fido2 | 0 to 8 | 1.0 |

  Readers MUST ignore slots of unknown type when unlocking, and MUST keep
  them when rewriting the vault.

### 4.2 Password slot (type 1)

```json
{ "kdf": "argon2id", "v": 19, "m_kib": 262144, "t": 3, "p": 4,
  "salt": "base64 of 16 to 32 random bytes" }
```

- V-20: `KEK = HKDF-SHA-256(IKM = Argon2id(NFC(password), salt, m_kib, t, p, L = 32),
  salt = vault_id, info = "rigel/v1/slot/password", L = 32)`.
- V-21: Bounds. Writers: `m_kib ≥ 65536` (64 MiB), `t ≥ 3`, `1 ≤ p ≤ 4`,
  salt 16 to 32 bytes. Readers additionally refuse `m_kib > 1048576`
  (1 GiB), `t > 64`, `p > 16`. These minimums are never lowered, not even in
  tests outside clearly marked test-only helpers (CLAUDE.md, rule 6).
- V-22: Calibration. When the slot is created or the password changes, the
  app measures this device and picks parameters for about 0.5 to 1 s:
  start at 256 MiB on desktop and 128 MiB on mobile (never below 64 MiB),
  `p` = min(4, CPU cores), then increase `t` until the target time is
  reached. The chosen values are stored in the slot.
- V-23: Minimum strength (proposal, to confirm in review): the password must
  have at least 10 characters after NFC and an estimated guess count of at
  least 10^10 (zxcvbn score 4, estimated in Rust). The app offers a generated
  passphrase of 5 words as an alternative. The same check applies to backup
  passphrases (backup-format.md).
- V-24: Failed attempts cause an increasing delay in the app (1, 2, 4 …
  up to 300 s). The counter lives in the unauthenticated `local_state` table
  (section 7); it only slows input in the app, not offline attacks, which is
  why V-23 exists. There is no wipe after failed attempts.
- V-25: Changing the password creates a new salt, recalibrates, and
  rewraps `VK`; records are not touched.
- V-26: In 1.0 every vault has exactly one password slot. Readers MUST NOT
  assume one exists, so that a later version can offer FIDO2-only vaults
  (open point 2) without a format change.

### 4.3 Recovery slot (type 2)

```json
{ "salt": "base64 of 16 random bytes" }
```

- V-30: The recovery code is 16 random bytes `R` (128 bits). Shown to the
  user as 32 characters of Base32 in 8 groups of 4:

  ```
  display = Base32(R || SHA-256("rigel/v1/recovery-check" || R)[0..4])
  shape:    XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX   (20 bytes = 32 characters)
  ```

  The last 4 bytes are a checksum that catches typing errors before any
  unwrap is attempted.
- V-31: Input is normalised: uppercase, spaces and hyphens removed, `0`→`O`,
  `1`→`I`, `8`→`B`. A wrong checksum gives "typing error" before unwrap.
- V-32: `KEK = HKDF-SHA-256(IKM = R, salt = params.salt, info = "rigel/v1/slot/recovery", L = 32)`.
  A slow KDF is not needed: `R` has 128 bits of entropy.
- V-33: The user must type the code back once during setup. After a
  recovery unlock, the app requires a new app password and shows a new
  recovery code (the old slot is replaced).
- V-34: Release 1.1 also derives the sync recovery key from `R`
  (sync-format.md). Replacing the recovery code therefore also re-wraps the
  sync recovery data.

### 4.4 Device slot (type 3)

The device slot lets Face ID, Touch ID, fingerprint or Windows Hello replace
typing the password. Biometrics only release a hardware-bound key; they are
never key material themselves.

Common params: `{ "platform": "...", "key_ref": "...", "salt": "base64 16 bytes", ... }`.
`key_ref` is the OS key alias or tag; it names, but does not contain, the key.

| `platform` | Mechanism | KEK |
| ---------- | --------- | --- |
| `apple-se` (iOS, iPadOS, macOS with Secure Enclave) | P-256 key in the Secure Enclave, access control `biometryCurrentSet` + `privateKeyUsage`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Params add `epk`: an ephemeral P-256 public key (SEC1 uncompressed, base64) created when the slot is made. | `HKDF(IKM = ECDH(se_key, epk), salt, info = "rigel/v1/slot/device/apple-se")` |
| `android-keystore` | AES-256-GCM key in Android Keystore, in StrongBox when available, `setUserAuthenticationRequired(true)` with `BIOMETRIC_STRONG`, `setInvalidatedByBiometricEnrollment(true)`, `setUnlockedDeviceRequired(true)`. Params add `iv` and `ct`: the Keystore encryption of a random 32-byte seed `S`. Unlock through `BiometricPrompt` with a `CryptoObject`. | `HKDF(IKM = S, salt, info = "rigel/v1/slot/device/android-keystore")` |
| `windows-hello` | Windows Hello key (`KeyCredentialManager`, TPM-backed when available). The key signs the fixed challenge `SHA-256("rigel/v1/slot/device/windows-hello" || salt)`; the signature is deterministic (RSA PKCS#1 v1.5). Params add `sig_check`: SHA-256 of the signature, to detect a changed key. | `HKDF(IKM = signature, salt, info = "rigel/v1/slot/device/windows-hello")` |
| (Linux) | none, by design: the system keyring is readable by every app of the user | — |

- V-35: When the OS invalidates the key (new biometric enrolment, device
  passcode removed), the slot fails; after a password unlock the app deletes
  and re-creates it.
- V-36: The device slot is optional and bound to this device. It is never
  part of backups or sync.
- V-37: Raw platform outputs (`S`, the ECDH secret, the signature) are
  handled inside `rigel-platform` and zeroed right after HKDF. Where the OS
  API forces them through Java/Kotlin or Swift memory (Android Keystore),
  that buffer is zeroed immediately after the call. This is the one
  accepted exception to "slot keys never leave Rust"; it is listed in the
  threat model as residual risk under T4.
- V-38: The Windows Hello mechanism and its determinism are confirmed in E5;
  if confirmed false, the alternative is an NCrypt TPM key (Microsoft
  Platform Crypto Provider) with a UI policy, using the same params layout
  with `platform = "windows-tpm"`.

### 4.5 FIDO2 slot (type 4)

```json
{ "credential_id": "base64", "rp_id": "rigel.invalid", "prf_salt": "base64 of 32 bytes",
  "uv": "required", "aaguid": "base64 of 16 bytes or null" }
```

- V-39: The slot uses the `hmac-secret` extension of CTAP2, or WebAuthn
  `prf` where the platform only offers WebAuthn (Windows, possibly iOS and
  Android). To get the same output on both paths, the CTAP salt is derived
  as in the WebAuthn PRF specification:

  ```
  hmac_salt = SHA-256("WebAuthn PRF" || 0x00 || prf_salt)
  KEK = HKDF-SHA-256(IKM = 32-byte hmac-secret output, salt = vault_id, info = "rigel/v1/slot/fido2", L = 32)
  ```

- V-41: User verification is always requested the same way for a slot
  (`uv` in params), because `hmac-secret` returns different values with and
  without UV. Default `required` (PIN or on-key biometrics); keys without
  UV support are registered with `discouraged` and the app warns.
- V-42: `rp_id` is a constant per vault. Its value is confirmed by the
  FIDO2 spike (iOS may require an associated domain); `rigel.invalid` is a
  placeholder.
- V-43: Registering two keys is recommended. The recovery slot stays
  mandatory, so a lost key never locks the user out.

## 5. Encrypted records

### 5.1 Envelope

All ciphertext in the vault (wrapped keys and records) uses one envelope:

```
envelope = envelope_version (u8, = 1) || nonce (24) || XChaCha20-Poly1305(key, nonce, plaintext, AAD)
```

- V-15: Readers refuse envelopes with an unknown `envelope_version`, a
  length below 1 + 24 + 16, or a failed tag check. Partial plaintext is
  never returned.

### 5.2 Record AAD

```
AAD_record = "rigel/v1/record" || 0x00 || vault_id (16) || record_id (16)
             || kind (u8) || schema_version (u16)
```

- V-17: The AAD binds a record to its vault, its ID, its kind and its schema
  version, so records cannot be swapped between entries, between kinds (for
  example a meta record presented as a secret record), between vaults, or
  replayed under another schema version.

### 5.3 Record kinds

| `kind` | Name | `record_id` | Key | Since |
| ------ | ---- | ----------- | --- | ----- |
| 1 | entry meta | entry UUID | `K_meta` | 1.0 |
| 2 | entry secret | entry UUID | `K_secret` | 1.0 |
| 3 | settings | `00000000-0000-4000-8000-000000000001` | `K_settings` | 1.0 |
| 4 | backup credential | `00000000-0000-4000-8000-000000000002` | `K_backup_cred` | 1.0 |
| 5 | sync state | `00000000-0000-4000-8000-000000000003` | `K_sync_state` | 1.1 |
| 6 | device identity | `00000000-0000-4000-8000-000000000004` | `K_device_identity` | 1.1 |

Readers MUST keep records of unknown kinds unchanged.

### 5.4 Plaintext encoding and padding

- V-18: Record plaintext is a JSON object (RFC 8259, UTF-8, no BOM),
  followed by ASCII spaces (0x20) that pad the plaintext to a multiple of
  256 bytes. Trailing whitespace is valid JSON, so no length field is needed.
  Padding hides the length of issuer and account names.
- V-19: JSON parsing of records uses the same limits as imports
  (backup-format.md, section 8). Decrypted buffers are `Zeroizing`; seeds
  are parsed from the buffer without intermediate `String` copies where the
  JSON library allows, and held as `SecretBox<[u8]>`.
- V-27: Readers MUST preserve unknown JSON members of a record when they
  rewrite it. This keeps fields that a newer version on another device wrote
  (sync, 1.1).

## 6. Entry schema (record schema version 1)

### 6.1 Field values

Every user-editable field is stored as `{"v": value, "t": "HLC"}`: the
value and the HLC time of its last change. The field-level times make
per-field "last writer wins" possible for sync in 1.1 without a migration.

### 6.2 Meta record (kind 1)

```json
{
  "created_at": "2026-10-25T20:15:00Z",
  "issuer":   { "v": "Example",                       "t": "0192f3a1b2c4-0000-8f1e2d3c4b5a6978" },
  "account":  { "v": "alice@example.com",              "t": "…" },
  "tags":     { "v": ["work"],                         "t": "…" },
  "favorite": { "v": false,                            "t": "…" },
  "sort_key": { "v": "a0",                             "t": "…" },
  "websites": { "v": ["example.com"],                  "t": "…" },
  "apps":     { "v": [{ "platform": "android", "id": "com.example.app",
                        "cert_sha256": ["base64…"] }], "t": "…" },
  "icon":     { "v": { "source": "builtin", "id": "example" }, "t": "…" },
  "note":     { "v": "",                               "t": "…" },
  "deleted":  { "v": false,                            "t": "…" }
}
```

| Field | Type and constraints |
| ----- | -------------------- |
| `created_at` | RFC 3339 UTC; set once |
| `issuer`, `account` | string, at most 256 bytes; may be empty, but not both |
| `tags` | array of distinct strings (1 to 64 bytes each), at most 64 |
| `favorite` | boolean |
| `sort_key` | fractional index string (`[0-9A-Za-z]`, 1 to 64 characters) for free ordering; lexicographic order |
| `websites` | array of at most 64 lowercase domain names (IDNA A-labels, no scheme, no path, no port), each with at least one dot |
| `apps` | array of at most 64 objects: `platform` = `android` (package name; optional `cert_sha256`, array of base64 SHA-256 signing-certificate digests) or `apple` (`TEAMID.bundle.id`) |
| `icon` | `null`, `{"source": "builtin", "id": string}` or, from 1.1, `{"source": "pack", "pack": UUID, "id": string}` |
| `note` | string, at most 4096 bytes |
| `deleted` | boolean; `true` is a tombstone kept for sync (section 6.5) |

### 6.3 Secret record (kind 2)

```json
{
  "otp": { "v": { "type": "totp", "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                  "algorithm": "SHA1", "digits": 6, "period": 30 }, "t": "…" },
  "counter":       { "v": 0, "t": "…" },
  "time_offset_s": { "v": 0, "t": "…" }
}
```

| Field | Type and constraints |
| ----- | -------------------- |
| `otp.type` | `totp`, `hotp` or `steam` |
| `otp.secret` | Base32, 1 to 256 bytes decoded |
| `otp.algorithm` | `SHA1`, `SHA256`, `SHA512` (`steam`: always `SHA1`) |
| `otp.digits` | 6 to 8 (`steam`: always 5, Steam alphabet) |
| `otp.period` | seconds, 1 to 3600, for `totp` and `steam` (`steam`: always 30) |
| `counter` | HOTP only: unsigned integer below 2^53; present only for `hotp` |
| `time_offset_s` | integer seconds, −3600 to 3600, added to the clock for this entry |

- V-28: `otp` is one value, because seed and parameters only make sense
  together; changing any of them replaces the whole value.
- V-29: `counter` is merged by maximum, not by time (a counter must never
  go back, or codes would repeat). The counter is incremented and stored
  before a HOTP code is shown.

### 6.4 HLC rules

- V-44: Each vault instance has a random 64-bit node ID (in the settings
  record). On every change: `t = max(previous_hlc, now)`, with the counter
  incremented when the millisecond part does not advance.
- V-45: A clock that jumps backwards never produces an HLC below the last
  one used on this device.

### 6.5 Deletion

- V-46: Deleting an entry sets `deleted.v = true`, replaces the secret
  record with a stub without `otp`, and keeps the meta record as a
  tombstone with only `created_at` and `deleted`. Without sync, tombstones
  are removed right away. With sync (1.1) they stay until all devices have
  seen them (sync-format.md).
- V-47: After deleting records the app runs `PRAGMA wal_checkpoint(TRUNCATE)`
  and `VACUUM`, with `secure_delete` on (section 7), so no old ciphertext
  remains in free pages or the WAL. Flash wear levelling can still keep old
  blocks; this is a residual risk, mitigated by encryption.

## 7. SQLite container

- V-50: The vault is one SQLite database file `vault.sqlite` in the app's
  private data directory (on iOS and macOS: the app group container shared
  with the AutoFill extension).

```sql
PRAGMA application_id = 1380404273;   -- 0x52474C31, "RGL1"
PRAGMA user_version = 1;              -- vault format version
PRAGMA journal_mode = WAL;
PRAGMA secure_delete = ON;
PRAGMA foreign_keys = ON;

CREATE TABLE vault_info (
  singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
  vault_id           BLOB    NOT NULL CHECK (length(vault_id) = 16),
  format_version     INTEGER NOT NULL,
  min_reader_version INTEGER NOT NULL
) STRICT;

CREATE TABLE slots (
  slot_id      BLOB    PRIMARY KEY CHECK (length(slot_id) = 16),
  slot_type    INTEGER NOT NULL,
  slot_version INTEGER NOT NULL,
  params       BLOB    NOT NULL,   -- JSON, non-secret, hashed into AAD_slot
  wrapped_key  BLOB    NOT NULL    -- envelope (section 5.1)
) STRICT, WITHOUT ROWID;

CREATE TABLE records (
  record_id      BLOB    NOT NULL CHECK (length(record_id) = 16),
  kind           INTEGER NOT NULL,
  schema_version INTEGER NOT NULL,
  envelope       BLOB    NOT NULL,
  PRIMARY KEY (record_id, kind)
) STRICT, WITHOUT ROWID;

-- Device-local, unauthenticated, never synced or backed up. Contains no
-- user data; tampering only changes the in-app delay (V-24).
CREATE TABLE local_state (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
) STRICT, WITHOUT ROWID;
```

- V-51: Apart from `local_state`, no column holds plaintext except opaque
  IDs, types and version numbers. In particular there are no plaintext
  timestamps, names or counts beyond what the number of rows reveals.
- V-52: Only the main app writes. The AutoFill extension opens the database
  read-only (`SQLITE_OPEN_READONLY`) and closes every connection before it
  is suspended, because iOS terminates processes that hold file locks in a
  shared container (`0xdead10cc`).
- V-53: `format_version` must equal `PRAGMA user_version`. A reader whose
  supported version is below `min_reader_version` refuses to open the vault
  (and says "update Rigel"); it never tries to repair or downgrade it.

Slot labels ("YubiKey blue") and app settings live in the encrypted settings
record, not in plaintext columns.

### 7.1 Settings record (kind 3)

Contains, among others: the HLC node ID, slot labels by `slot_id`, lock
timeouts, clipboard timeout (default 30 s), hide-codes setting, automatic
backup configuration (off by default; folder reference and number of kept
versions), sort mode. Fields are `{"v", "t"}` like entries. The exact list
is maintained in `docs/schemas/vault-settings-v1.schema.json` (E4).

### 7.2 Backup credential (kind 4)

Present only when automatic backups are on:
`{"type": "passphrase", "passphrase": "…"}` or, once supported
(backup-format.md, B-6), `{"type": "age-identity", "identity": "AGE-SECRET-KEY-…"}`.

## 8. AutoFill matching

- V-40: A code is offered to AutoFill only for entries that match the
  request:
  - **Web:** the request host `h` matches a website `w` when `h == w` or `h`
    ends with `"." + w`. `w` must not be a public suffix (checked against a
    bundled copy of the Public Suffix List).
  - **Android apps:** the package name equals `apps[].id`, and when
    `cert_sha256` is present, the requesting app's signing certificate digest
    is one of them.
  - **Apple:** the service identifier given by the system (domain or URL) is
    matched like a website.
- V-48: When an entry is created from an otpauth URI, which has no domain,
  the app suggests domains from a bundled, curated issuer-to-domain list.
  The user confirms; nothing is looked up online.

## 9. Lifecycle

1. **Create:** generate `vault_id`, `VK`, node ID; create password and
   recovery slots; write `vault_info` and an empty settings record.
2. **Unlock:** read slots; run the selected slot's derivation; unwrap `VK`;
   derive purpose keys; decrypt meta records for the list.
3. **Compute a code:** decrypt the entry's secret record, compute, zero the
   plaintext; return digits and remaining seconds to the UI.
4. **Lock:** zero `VK`, purpose keys and all decrypted data (CLAUDE.md,
   rule 2).
5. **Rekey (optional):** new `VK`; re-encrypt all records and rewrap all
   slots in one transaction, after a snapshot.

## 10. Migrations and snapshots

- V-60: Before any migration of the vault format or of a record schema, the
  app writes a snapshot with `VACUUM INTO` to `snapshots/vault-v<old
  version>-<UTC time>.sqlite` next to the vault. The snapshot is as
  encrypted as the vault itself.
- V-61: A migration runs in one transaction. On any error the vault stays
  at the old version, and the snapshot is kept.
- V-62: The app keeps the three newest snapshots, and always the one from
  before the most recent migration until the migrated vault has been
  unlocked successfully once.
- V-63: Every format version has stored test vaults in
  `docs/formats/vault/v<N>/` (created in E4). Each migration is tested
  against all of them.
- V-64: Version numbers only increase. A vault written by a newer version
  is never opened for writing by an older one (V-53).

## 11. Test vectors

E4 adds deterministic test vectors under `docs/formats/vault/v1/`: fixed
`VK`, `vault_id`, salts and nonces (test-only helper), the expected purpose
keys, slot envelopes and record envelopes, using only RFC test seeds.

## 12. Open points for review

1. Minimum password strength (V-23): 10^10 guesses and 10 characters, or
   stricter.
2. FIDO2-only vault without password (the plan allows it, 1.0 requires a
   password): decide for 1.1 or later; the format already allows it (V-26).
3. `rp_id` for FIDO2 (V-42) after the spike.
4. Windows device slot mechanism (V-38) after E5.

## Changelog

- Draft 1 (2026-10-25): first version.
