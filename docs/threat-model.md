# Rigel threat model

Status: Draft 1 (2026-10-25), for review. Covers releases 1.0 to 1.2.

This document says what Rigel protects, against whom, and where it
deliberately stops. Every security requirement (`SR-…`) is implemented and
tested somewhere; the specs reference these IDs.

## 1. System overview

Rigel is an offline TOTP/HOTP authenticator for Android, iOS/iPadOS, macOS,
Windows and Linux.

```
 ┌────────────────────────── user's device ───────────────────────────┐
 │                                                                     │
 │  Flutter UI (Dart)          AutoFill extension / Autofill service   │
 │  untrusted for secrets      (Swift / Kotlin), read-only vault       │
 │        │ ffi-dart                     │ ffi-uniffi                  │
 │  ══════╪══════════════ TB1: FFI boundary ═════╪═══════════════════  │
 │        ▼                              ▼                             │
 │        rigel-platform ── TB2 ── OS key store (SE / Keystore / TPM)  │
 │        │                └─ TB3 ── FIDO2 security key (USB / NFC)    │
 │        rigel-core (all secrets, all parsing)                        │
 │        │                                                            │
 │  ══════╪══════════════ TB4: storage ══════════════════════════════  │
 │        ▼                                                            │
 │   vault.sqlite (per-record AEAD)    snapshots    backup folder      │
 └────────┼──────────────────────────────────────────┼─────────────────┘
          │ TB5: files leave the device              │
          ▼                                          ▼
   sync folder (1.1, cloud / Syncthing)     backups on USB stick, cloud…
```

Trust boundaries:

- **TB1, FFI boundary.** Dart, Swift and Kotlin memory cannot be reliably
  zeroed and is visible to more code (plugins, the framework). Vault keys
  and slot keys never cross TB1. Seeds cross it only in two places (manual
  entry into Rust, confirmed plaintext export out of Rust).
- **TB2, OS key store.** Trusted to keep hardware-bound keys and to enforce
  biometric or device-credential checks. Not trusted with data.
- **TB3, security key.** Trusted to compute `hmac-secret`/PRF only for its
  own credential and with user presence.
- **TB4, local storage.** Everything on disk is assumed readable by an
  attacker who copies the files. Only ciphertext and opaque IDs are stored.
- **TB5, outside the device.** Backup files and the sync folder are
  assumed fully attacker-controlled: readable, modifiable, replayable,
  deletable.

Rigel makes **no network connections** at all. There is no Rigel server,
no account and no telemetry.

## 2. Assets

| ID | Asset | Why it matters |
| -- | ----- | -------------- |
| A1 | OTP seeds (TOTP/HOTP/Steam secrets) | Whoever has a seed can generate the second factor forever, unnoticed |
| A2 | Vault key and the keys derived from it | Opens A1 and A3 |
| A3 | Metadata: issuers, account names, domains, app IDs, tags, notes | Reveals which services and accounts someone has |
| A4 | Unlock secrets: app password, recovery code, backup passphrase, sync key | Lead to A2 |
| A5 | Availability of the user's own data | Losing seeds can lock people out of their accounts |
| A6 | Integrity of codes and entries | A swapped seed or domain can lock out or mislead the user |
| A7 | Integrity of the shipped app | A malicious build defeats every other control |

Generated one-time codes are short-lived and less valuable than seeds, but
are still protected (clipboard, screen) because they can be phished or
replayed within their window.

## 3. Assumptions

- The OS kernel, the secure hardware (Secure Enclave, StrongBox/TEE, TPM)
  and the platform's crypto RNG work as documented.
- The user's device is not rooted, jailbroken or infected with malware that
  has root or debugging rights. If it is, Rigel can only slow an attacker
  down (section 6).
- The user chooses an app password that passes the enforced minimum
  strength and keeps the recovery code offline.
- Compilers, the Rust toolchain, Flutter and the audited crypto crates are
  correct. Supply-chain controls (section 5.8) reduce, not remove, this risk.

## 4. Adversaries

| ID | Adversary | Capabilities | Goal |
| -- | --------- | ------------ | ---- |
| T1 | Thief with a locked device | Physical access, no device passcode, may image storage, may attack hardware | A1, A3 |
| T2 | Person at the unlocked device | Short physical access, shoulder surfing, screenshots | A1, codes |
| T3 | Malicious app without root | Runs in its own sandbox; can read the clipboard (with OS limits), abuse accessibility services, send intents, read shared storage | A1, A3, codes |
| T4 | Malware with root / jailbreak | Reads process memory, hooks APIs, keylogs | everything |
| T5 | Thief of a backup file | Unlimited offline guessing against the file | A1, A3 |
| T6 | Sync storage provider or anyone with the folder (1.1) | Reads, modifies, deletes, withholds and replays every file in the folder | A1, A3, A6 |
| T7 | Network attacker | Observes and modifies traffic | anything sent over the network |
| T8 | Crafted input author | Supplies hostile QR codes, otpauth URIs, import files, backups, journals, icon packs | code execution, crashes, data corruption |
| T9 | Supply-chain attacker | Compromises a dependency, a CI action, a maintainer account or the build | A7 |
| T10 | Rigel itself (bugs, bad updates) | A faulty migration or update | A5 |
| T11 | Phishing site | Tricks the user into entering a code on the wrong site | codes |
| T12 | Coercion | Forces the user to unlock | everything |

## 5. Threats and mitigations

### 5.1 T1, thief with a locked device

- SR-1: The vault key is stored only wrapped in unlock slots; at rest no key
  and no plaintext record exists on disk (vault-format.md, V-1 to V-6).
- SR-2: Device slots use keys that are bound to the device's secure hardware
  and require user authentication (Secure Enclave, Android Keystore with
  StrongBox when present, TPM through CNG). Keychain items are
  `ThisDeviceOnly`.
- SR-3: The password slot uses Argon2id with at least 64 MiB memory and a
  device-calibrated time of about 0.5 to 1 s; the app password must pass an
  enforced minimum strength (vault-format.md, V-20 to V-24).
- SR-4: Every record, including issuer and account name, is encrypted
  individually; the database contains only opaque IDs, versions and
  ciphertext.

Residual risk: hardware attacks on the secure element. On Linux, which has
no device slot by design (section 7), a copied vault file can be attacked
offline; the password strength and Argon2id cost are the only barrier.

### 5.2 T2, person at the unlocked device

- SR-5: Rigel has its own lock, independent of the device lock: mobile locks
  immediately when the app goes to the background; desktop locks after 5
  minutes of inactivity, on screen lock and on sleep (both configurable).
- SR-6: Codes can be hidden until tapped. Screenshots and screen recording
  are blocked where the platform allows (Android `FLAG_SECURE`, iOS/macOS
  privacy overlay, Windows `WDA_EXCLUDEFROMCAPTURE`). The app-switcher
  preview is hidden.
- SR-7: Unlocking after a failed password attempt is delayed with an
  increasing wait time. There is no automatic wipe after failed attempts,
  because that risks data loss (A5).
- SR-8: Viewing a seed, the plaintext export and turning off the lock
  require a fresh unlock.

Residual risk: coercion (T12) is out of scope; Rigel offers no duress mode.

### 5.3 T3, malicious app without root

- SR-9: No exported Android components except the launcher activity; no
  custom URL scheme or intent that returns data; no content providers.
- SR-10: Copied codes are marked sensitive (Android 13+ `EXTRA_IS_SENSITIVE`),
  local-only with an expiry on iOS (`UIPasteboard` `localOnly`,
  `expirationDate`), excluded from Windows clipboard history and cloud
  clipboard, and cleared after 30 s by default.
- SR-11: Android auto-backup and device-to-device transfer are disabled; no
  data in shared or external storage except files the user exports.
- SR-12: AutoFill offers a code only when the requesting domain or app ID
  matches the entry's `websites[]` or `apps[]` (vault-format.md, V-40).
  This blocks a malicious app from receiving codes for other services.
- SR-13: No secrets, issuers or account names in logs, error messages,
  `Debug` output, crash dumps or notifications.

Residual risk: accessibility services granted by the user can read the
screen. Linux clipboard managers (for example Klipper) may store copied
codes regardless of hints.

### 5.4 T4, malware with root or jailbreak

- SR-14: Secrets are held in `secrecy`/`zeroize` types and zeroed on lock;
  seeds are decrypted only for the duration of a code computation, and the
  UI receives digits and remaining time, never a seed.
- SR-15: The app warns, but does not refuse to run, on rooted or jailbroken
  devices.

Residual risk: out of the protection goal. Malware with root can read memory
while the vault is unlocked and keylog the password.

### 5.5 T5, thief of a backup file

- SR-16: Backups use the open `age` format with a passphrase recipient
  (scrypt, work factor targeting about 1 s) (backup-format.md, B-1 to B-12).
- SR-17: The backup passphrase must pass the same minimum strength check as
  the app password. The app can test a backup (decrypt and compare) without
  changing anything.
- SR-18: Automatic backups are off by default. When enabled, they use a
  separate backup key chosen by the user, so a backup can be restored
  without the vault, and the vault password is never written into backups.
- SR-19: The plaintext payload is padded to a multiple of 4 KiB, so the
  file size reveals the number of entries only coarsely.

Residual risk: a weak passphrase that still passes the strength check;
unlimited offline guessing is possible by design.

### 5.6 T6, sync storage provider (release 1.1)

- SR-20: Everything in the sync folder is end-to-end encrypted: entries,
  device list, membership and pairing data. File names are random IDs
  (sync-format.md).
- SR-21: Journals are signed by device keys (Ed25519) and carry monotonic
  counters and hash chains, so modification, reordering and rollback behind
  the last seen state are detected.
- SR-22: Ciphertext sizes are padded to fixed buckets.
- SR-23: Device pairing authenticates through a QR code shown on the new
  device; the folder cannot inject a key without being detected.
- SR-24: Key exchange and key distribution use a hybrid post-quantum KEM
  (X25519 + ML-KEM-768), against "harvest now, decrypt later".
- SR-25: Removing a device rotates the sync key and re-encrypts the data.

Residual risk: the provider sees when files change, how many devices write
and size buckets. Withholding new journals can be detected only to a
limited extent. A removed device keeps the seeds it already knew; the app
tells the user to rotate those seeds at the services if the device is
compromised.

### 5.7 T7, network attacker

- SR-26: Rigel contains no network code. Where the OS has a network
  permission (Android, macOS sandbox, Flatpak) it is absent and verifiable;
  iOS and Windows have no such permission. CI fails the build if network
  crates, Dart HTTP packages, Android network permissions or macOS network
  entitlements appear (`tools/ci/check_policy.py`, `core/deny.toml`).
- SR-27: No favicon download, no update check, no remote icon packs.
  Browser extensions (1.1) talk to the desktop app only through local
  Native Messaging.

Residual risk: none from Rigel's own traffic, because there is none. Sync
traffic belongs to the sync service, which sees only ciphertext (T6).

### 5.8 T8, crafted input

- SR-28: Every untrusted input (QR images, otpauth URIs, import files,
  backups, sync files, icon packs) is parsed in Rust only, with size limits
  checked before allocation, without panics on malformed input, and with a
  `cargo-fuzz` target per parser. Limits are in backup-format.md, section 8.
- SR-29: QR images are decoded in Rust (for example `rqrr`), not through ML
  Kit or other services. SVG icons are sanitised (no scripts, no external
  references) before use.
- SR-30: Imports show a preview and never overwrite existing entries
  without confirmation.

### 5.9 T9, supply chain

- SR-31: Few dependencies; `cargo-deny` (license allowlist without
  third-party GPL, ban list for network crates, advisories, source
  restrictions) and `cargo-vet` in CI; the same restraint for Dart packages.
- SR-32: CI uses no third-party actions; anything added later is pinned to
  a commit SHA (`pinned-actions` check). Protected `main`, signed commits,
  DCO sign-off, hardware-key 2FA for maintainers.
- SR-33: Reproducible builds, signed release artifacts (Sigstore or
  minisign) and an SBOM per release (E16).
- SR-34: External security audit before 1.0; private vulnerability
  reporting from the first public commit (`SECURITY.md`).

Residual risk: a compromised maintainer account; malicious code in an
audited dependency that slips past review.

### 5.10 T10, faulty update

- SR-35: Every data migration is preceded by an encrypted snapshot of the
  vault; migrations are tested against stored files of every older format
  version (vault-format.md, V-60 to V-64).
- SR-36: Old test files are never deleted; format versions only move
  forward; unknown newer versions are refused read-only, never "repaired".

### 5.11 T11, phishing

TOTP codes cannot be protected against real-time phishing; only passkeys of
the services themselves help, and managing passkeys is a non-goal of Rigel.
Domain matching in AutoFill (SR-12) reduces the risk, because the code is
offered only on the matching site.

## 6. Cryptographic considerations

- **No home-made cryptography.** Rigel composes audited primitives only:
  XChaCha20-Poly1305, Argon2id, HKDF-SHA-256, SHA-2, X25519, ML-KEM-768,
  Ed25519 and the `age` format (RustCrypto crates and `rage`).
- **SHA-1 in TOTP.** HMAC-SHA-1 remains secure; collision attacks on SHA-1 do
  not break HMAC. The service chooses the algorithm; Rigel supports SHA-256
  and SHA-512 where offered.
- **Quantum computers.** TOTP is symmetric. Grover's algorithm halves the
  effective key length (a 160-bit seed keeps about 80 bits), and an attacker
  would first need observed codes. Rigel's symmetric parts (vault, password
  backups) use 256-bit keys. Only asymmetric parts are exposed to
  "harvest now, decrypt later": the sync key exchange and backup recipient
  keys. These use hybrid X25519 + ML-KEM-768. Ed25519 signatures are less
  urgent, because a forgery would have to happen at verification time.

## 7. Platform decisions with security impact

- **Linux has no device slot.** The Secret Service / system keyring is
  readable by every application of the user and adds no protection against
  T3. Linux users unlock with the password or a FIDO2 key.
- **iOS/macOS AutoFill extension** unlocks only through Face ID/Touch ID or a
  FIDO2 key, never through the password, because Argon2id can exceed the
  extension's memory limit. The extension opens the vault read-only.
- **Biometrics are never a key.** They only release a hardware-bound key. If
  the enrolled biometrics change, the biometric slot becomes invalid and the
  password re-creates it.
- **No periodic password prompt.** Users who want it can disable biometrics.

## 8. Out of scope

- Attacks requiring a fully compromised OS (T4), except slowing them down.
- Coercion (T12) and duress features.
- Phishing of codes (T11) beyond domain matching.
- Side channels of shared hardware (for example cache timing from other
  VMs) beyond what the used constant-time primitives provide.
- Platforms and OS versions below the supported minimums (iOS 17,
  Android 9, Windows 10, macOS 13, current LTS distributions).

## 9. Open points for review

1. Exact minimum password strength (proposal in vault-format.md, V-23).
2. Whether to offer an optional duress or "panic lock" feature later.
3. Results of the M0 spikes (FIDO2 on Windows and iOS, AutoFill memory
   budget, QR decoding in Rust) may change sections 5.1 and 7.

## Changelog

- Draft 1 (2026-10-25): first version, from the reviewed architecture plan.
