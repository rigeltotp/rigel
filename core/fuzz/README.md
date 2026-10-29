# Fuzz targets

One `cargo-fuzz` target per parser of untrusted input (otpauth URIs, QR
payloads, import files, backups, sync journals, icon packs), added together
with the parser it covers (SR-28). This directory is its own Cargo workspace,
so `libfuzzer-sys` never enters the app's `Cargo.lock`.

| Target | Parser |
| ------ | ------ |
| `otpauth` | `rigel_core::otp::otpauth::parse` |
| `qr_image` | `rigel_core::qr::decode_image_file` (PNG, JPEG) and `LumaImage::from_luma_plane` |

```sh
cd core/fuzz
cargo +nightly fuzz run <target>                         # until stopped
cargo +nightly fuzz run <target> -- -max_total_time=60   # smoke run
```

`corpus/` and `artifacts/` are not committed (`.gitignore`). A crash found
by fuzzing becomes a regular unit test next to the parser.
