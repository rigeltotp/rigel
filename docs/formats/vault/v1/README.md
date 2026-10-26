# Vault test files, format version 1

Never edit or delete files in this directory (docs/README.md).

`records/` holds plaintext record documents (before encryption and padding).
`valid-*` must validate against the schemas in `docs/schemas/`, `invalid-*`
must be rejected. Encrypted vectors (fixed keys, salts, nonces; slots; a whole
`vault.sqlite`) are added with E4, together with the implementation that
produces them.
