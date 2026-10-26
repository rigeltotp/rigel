# Sync format (release 1.1)

Status: Draft 1 (2026-10-25). The **data model is frozen** for the vault
(vault-format.md already carries every field sync needs); the **protocol
details** below are a reviewed proposal and are finalised in E12.
Implemented by: `rigel-core` (`sync`), `rigel-platform` (folder access).

Sync is off by default. It works only through a folder that an existing sync
service keeps in step (iCloud Drive, Nextcloud, Syncthing, Dropbox, a USB
stick moved by hand). There is no Rigel server, and the app itself never
opens a network connection.

## 1. Goals and threat model

The folder and everyone who can read or write it are untrusted (threat
model, T6). Sync must provide:

- S-1: **Confidentiality.** Nothing in the folder is plaintext: entries,
  device list, membership, pairing data and file names reveal nothing.
- S-2: **Integrity and authenticity.** Every change is signed by a member
  device; modified, reordered, injected or replayed files are detected.
- S-3: **Rollback detection.** A device notices when the folder shows a state
  older than one it has seen. Withholding of new files is detected only in
  part (section 7).
- S-4: **No write conflicts in the sync service.** Every file has exactly one
  writer (with the rare exception in S-31).
- S-5: **Post-quantum key exchange.** Keys are distributed with a hybrid KEM
  (X25519 + ML-KEM-768).
- S-6: **Revocation.** Removing a device rotates the group key.

Non-goals: real-time sync, sync without a folder, hiding *when* files change
or how many devices write.

## 2. Primitives

| Purpose | Primitive |
| ------- | --------- |
| File encryption | XChaCha20-Poly1305 envelope as in vault-format.md, section 5.1 |
| Key derivation | HKDF-SHA-256 |
| Signatures | Ed25519 (RFC 8032), strict verification |
| Key encapsulation | HPKE (RFC 9180) base mode with KEM X-Wing (X25519 + ML-KEM-768), KDF HKDF-SHA-256, AEAD ChaCha20-Poly1305 |
| Hash | SHA-256 |

- S-7: The X-Wing KEM is used as implemented by the RustCrypto `hpke` crate
  (feature `mlkem`), pinned to an exact version and checked against the
  draft's test vectors, because X-Wing is still an IETF draft. E12 decides
  whether to wait for the final RFC.

## 3. Keys and identities

- S-10: **Device identity** (vault record kind 6, never leaves the device):
  random 16-byte `device_id`, an Ed25519 signing key pair and an X-Wing key
  pair. Created when the device first joins a group.
- S-11: **Group** = random 16-byte `group_id` plus a sequence of **epochs**.
  Each epoch `n` has a random 32-byte group key `GK_n`. From it:

  ```
  K_file_n = HKDF(IKM = GK_n, salt = group_id, info = "rigel/v1/sync/file" || u32(n))
  K_name_n = HKDF(IKM = GK_n, salt = group_id, info = "rigel/v1/sync/name" || u32(n))
  ```

- S-12: **Recovery keys** are derived from the recovery code `R` of the
  vault that created the group (vault-format.md, V-30) or of the device that
  last re-keyed recovery (S-42):

  ```
  seed_kem = HKDF(IKM = R, salt = group_id, info = "rigel/v1/sync/recovery-kem")    → X-Wing key pair
  seed_sig = HKDF(IKM = R, salt = group_id, info = "rigel/v1/sync/recovery-sig")    → Ed25519 key pair
  name_rec = HKDF(IKM = R, salt = "",       info = "rigel/v1/sync/recovery-name", L = 16)
  ```

  Only the public keys are stored in the group. Any member can therefore
  wrap new group keys to the recovery key without knowing `R`.

## 4. Folder layout

- S-20: All files lie flat in the folder the user chose. File names are 32
  lowercase hex characters without extension; they are random to the
  provider, but members compute them:

  ```
  name(type, parts…) = hex(HKDF(IKM = K_name_n, info = "rigel/v1/sync/name/" || type || parts, L = 16))
  ```

  Exceptions: pairing files (named from the pairing secret, section 6) and
  the recovery file (named `hex(name_rec)`).
- S-21: Every file is one envelope (`version || nonce || ciphertext`). The
  AAD binds `group_id`, epoch, file type and file name, so a file cannot be
  renamed or moved into another role.
- S-22: Plaintext inside files is padded to the next bucket: 1, 4, 16, 64,
  256 KiB, 1 MiB, then multiples of 1 MiB.

| File type | Writer | Name parts | Content |
| --------- | ------ | ---------- | ------- |
| `member` | any member | epoch, sequence | membership record (section 5) |
| `keywrap` | the member that made the epoch | epoch, `device_id` | HPKE-wrapped `GK_n` for one member |
| `journal` | its author device | epoch, `device_id`, sequence | journal segment (section 7) |
| `checkpoint` | its author device | epoch, `device_id`, sequence | full state snapshot (section 8) |
| `pairing-offer`, `pairing-answer` | new device / member | from pairing secret | section 6 |
| `recovery` | any member | from `R` | HPKE-wrapped `GK_n` for the recovery key |

## 5. Membership

- S-30: Membership is a hash chain of signed records. Each record contains:
  `group_id`, `epoch`, `seq`, `prev` (SHA-256 of the previous record),
  `members[]` (per device: `device_id`, Ed25519 public key, X-Wing public
  key, encrypted display name, added time), `revoked[]` (device IDs),
  recovery public keys, the signer's `device_id` (or `recovery`), and an
  Ed25519 signature over
  `"rigel/v1/sync/member" || 0x00 || SHA-256(record without signature)`.
- S-31: **Authority.** A record is valid when it is signed by a device that
  is a member in the previous record, or by the group's recovery signing
  key. The first record (`epoch 0, seq 0`) is signed by the creating device.
  This is the decision the architecture plan left to this spec: *every
  member device may change membership; the recovery key may too; no single
  owner device exists*, so losing any one device never locks the group.
- S-32: **Adding a device** appends a record in the current epoch and writes
  a `keywrap` for the new device. The group key does not change.
- S-33: **Removing a device** starts epoch `n+1`: a fresh `GK_{n+1}`, a
  membership record that moves the device to `revoked[]`, a `keywrap` for
  every remaining member and an updated `recovery` file. The removing device
  then writes a checkpoint (section 8) under the new epoch, so the remaining
  data is re-encrypted. Files of old epochs are deleted once every remaining
  member has acknowledged the new epoch.
- S-34: **Concurrent changes.** If two valid records claim the same
  `(epoch, seq)`, the one with the lower SHA-256 hash wins on every device;
  the device whose record lost re-applies its change on top of the winner.
- S-35: The app tells the user that a removed device keeps the seeds it
  already knew, and recommends changing them at the services if the device
  was lost or stolen.

## 6. Adding a device (pairing)

Both devices must already see the same folder.

1. The new device `N` creates its device identity and a random 32-byte
   pairing secret `P`. It writes a `pairing-offer` file named
   `hex(HKDF(P, info = "rigel/v1/sync/pairing-offer-name", L = 16))`,
   encrypted with `HKDF(P, info = "rigel/v1/sync/pairing-offer")`,
   containing its Ed25519 and X-Wing public keys and display name.
2. `N` shows a QR code with `rigel-pair:1:` followed by base64url (no
   padding) of `P || H`, where `H` is the first 16 bytes of SHA-256 of the
   offer's plaintext.
3. A member `M` scans it, reads the offer, checks `H` and shows the device
   name for confirmation. The QR code is the authentic channel: the folder
   cannot substitute keys, because they would not match `H`.
4. `M` appends a membership record adding `N` (S-32) and writes a
   `pairing-answer` (named and encrypted from `P` like the offer) containing
   an HPKE encapsulation to `N`'s X-Wing key of: `group_id`, current epoch,
   `GK_n` and the hash of the newest membership record.
5. `N` decrypts the answer, verifies the membership chain up to that hash,
   and starts syncing. Both pairing files are deleted.

- S-40: An offer expires after 15 minutes; members refuse older offers.

## 6.1 Restoring without another device

- S-41: A device without any other member uses the recovery code: it
  derives the recovery keys (S-12), reads the `recovery` file, decrypts
  `GK_n`, verifies the membership chain, and adds itself with a membership
  record signed by the recovery signing key.
- S-42: After a recovery, or when the user replaces the recovery code on
  the device that owns it, that device re-keys recovery: it publishes new
  recovery public keys in a membership record and rewrites the `recovery`
  file. The app shows which device's recovery code restores sync.

## 7. Journals

- S-50: Each device writes its own append-only sequence of journal
  segments per epoch. A segment contains: `device_id`, `epoch`, `seq`,
  `prev` (hash of the previous segment of this device), the author's
  **version vector** (highest `seq` seen per device), and `ops[]`.
- S-51: An op sets fields of one entry record:
  `{ "entry": UUID, "kind": 1 | 2, "fields": { name: { "v": …, "t": HLC } } }`.
  Values and HLC strings are exactly those of the vault (vault-format.md,
  section 6).
- S-52: Merge rules: per field, the higher HLC wins (byte-wise compare,
  which includes the node ID as tie-breaker); `counter` merges by maximum;
  unknown fields are kept (V-27).
- S-53: Each segment is signed by its author:
  `"rigel/v1/sync/journal" || 0x00 || group_id || u32(epoch) || device_id || u64(seq) || SHA-256(body)`.
  Segments from revoked devices, or for epochs in which the author was not a
  member, are ignored.
- S-54: **Rollback detection.** Each device stores in its sync state record
  (vault kind 5) the newest `(epoch, seq, hash)` it has accepted per device
  and the newest membership hash. A folder showing anything older raises a
  warning and sync pauses for that device until the user decides.
- S-55: **Withholding** is detected only partially: when another device's
  version vector shows a segment that this device cannot find, the app shows
  "data from device X is missing in the folder" after a grace period.

## 8. Checkpoints and garbage collection

- S-60: A device may write a checkpoint: the full merged state of all
  entries (including tombstones) and its version vector. Segments of the
  same author that the checkpoint covers can be deleted once every member's
  version vector covers them.
- S-61: Tombstones (`deleted = true`) are removed from vaults and
  checkpoints once every current member has acknowledged them.

## 9. Open points for E12

1. Wait for the X-Wing RFC or ship with the pinned draft version (S-7).
2. Which recovery code restores sync when several devices were set up
   independently (S-12, S-42); proposal above: the code of the device that
   created the group or last re-keyed recovery, shown in the app.
3. Exact bucket sizes and the debounce interval for writing segments.
4. Behaviour of providers that create conflict copies of files despite
   S-4 (expected only for the `recovery` file); proposal: members accept the
   copy with the higher epoch and rewrite it.

## Changelog

- Draft 1 (2026-10-25): first version; settles the membership authority
  question left open by the architecture plan (S-31).
