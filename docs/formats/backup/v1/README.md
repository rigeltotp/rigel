# Backup test files, schema version 1

Never edit or delete files in this directory (docs/README.md). All seeds are
the RFC 6238 test seed or fake; the passphrase below protects nothing.

| File | Meaning |
| ---- | ------- |
| `valid-*.json` | must validate against `docs/schemas/backup-v1.schema.json` and import |
| `invalid-*.json` | must be rejected; the name says why |
| `valid-full.rigel.age` | age file, passphrase in `valid-full.passphrase`; plaintext is `valid-full.json` plus a line feed and space padding to a multiple of 4096 bytes (B-7). Decrypts with the plain `age` tool |
| `invalid-truncated.rigel.age` | first 1500 bytes of the file above; must be rejected |
| `invalid-not-age.rigel.age` | not an age file; must be rejected |

Checked by `tools/ci/check_formats.py` (schemas) and
`tools/ci/check_backup_interop.sh` (age CLI).
