# Fuzz targets

One `cargo-fuzz` target per parser of untrusted input (otpauth URIs, QR
payloads, import files, backups, sync journals, icon packs). Targets are added
together with the parser they cover, starting with E3.

```sh
cd core/fuzz
cargo +nightly fuzz run <target>
```

This directory becomes its own (non-workspace) crate when the first target
lands, as `cargo fuzz init` sets it up.
