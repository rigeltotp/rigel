# Spike `qr-rust`: QR decoding in Rust

**Question.** Does `rqrr` (or an alternative) decode real-world screenshots
and camera frames reliably enough to be Rigel's only QR decoder (SR-29)?

**Answer.** `rqrr` does not: it reads about two thirds of screenshots and
under half of the camera frames that the reference decoder reads, and it
panicked within five minutes of fuzzing. `rxing` (a pure-Rust port of ZXing)
comes close to the C++ ZXing reference: 99.4 % of screenshots and 89.9 % of
camera frames that the reference reads, in about 11 ms per image, and its
fuzz run found no crash. **Recommendation: `rxing`**, with the conditions in
"Recommendation" below. Status: done 2026-10-28, decision pending (R).

## Method

- **Data set** (`qr-rust/gen_images.py`, seeded, reproducible): 1280
  synthetic grayscale images, fake seeds only (rule 18). Four payloads:
  short TOTP URI (~80 chars), medium (~150), long with an `image` URL
  (~330), and a Google-Authenticator-style `otpauth-migration` batch
  (~600 chars, QR version 16–25).
  - 640 **screenshots**: 1080×2400 canvas with UI clutter; module size 2–8
    px, then scaled by 0.6–1.6 (non-integer DPI, bilinear); ECC L/M/Q/H;
    quiet zone 4, 2 or 1 modules; 25 % dark mode (inverted); 30 % JPEG q70.
  - 640 **camera-like frames**: 1280×720; QR on a card covering 20–65 % of
    the frame height; any rotation; perspective tilt up to 25 %; Gaussian
    blur 0–2.5 px; uneven light; contrast 0.35–1; noise σ 0–20; JPEG q40–85.
- **Reference:** zxing-cpp 2.3.0 (Python binding, with an inverted retry),
  to separate "hard for everyone" from "hard for this decoder"
  (`qr-rust/reference_zxing_cpp.py`).
- **Candidates:** `rqrr` 0.11.0, `rxing` 0.9.3 (features `decoders`,
  `qrcode`, `encoding_rs`), `bardecoder` 0.5.0 (on every 5th image).
  Variants: an inverted retry for dark mode; for `rqrr` also a 2× upscale
  retry; for `rxing` also `TryHarder` (`qr-rust/harness.rs`). A hit is an
  exact match of the decoded text; wrong texts were counted separately.
- **Robustness:** 5 minutes of `cargo fuzz` per decoder on raw luma
  buffers, seeded with small valid QR images.
- One core of the cloud VM, release build.

## Results

Hit rate over all images, and over the images the reference decodes:

| Decoder | Screenshots | of reference-decodable | Camera-like | of reference-decodable | Time per image |
| ------- | ----------- | ---------------------- | ----------- | ---------------------- | -------------- |
| zxing-cpp (reference) | 631/640 (98.6 %) | — | 336/640 (52.5 %) | — | — |
| `rqrr` | 302/640 (47.2 %) | — | 157/640 (24.5 %) | — | 25 ms |
| `rqrr` + inverted retry | 408/640 (63.8 %) | 406/631 (64.3 %) | 157/640 (24.5 %) | 157/336 (46.7 %) | 38 ms |
| `rqrr` + inverted + 2× upscale | 511/640 (79.8 %) | 507/631 (80.3 %) | 221/640 (34.5 %) | 218/336 (64.9 %) | 326 ms |
| `rxing` | 311/640 (48.6 %) | — | 295/640 (46.1 %) | — | 7 ms |
| **`rxing` + TryHarder + inverted retry** | **630/640 (98.4 %)** | **627/631 (99.4 %)** | **304/640 (47.5 %)** | **302/336 (89.9 %)** | **11 ms** |
| `bardecoder` | 68/128 (53.1 %), dark mode 0 % | — | 9/128 (7.0 %) | — | 67 ms |

The camera set is deliberately harsh (the reference reads only half of it);
the column against the reference is the meaningful one. Selected groups for
`rxing` (+TryHarder, inverted) against `rqrr` (+inverted):

| Group | `rxing` | `rqrr` | Reference |
| ----- | ------- | ------ | --------- |
| Screenshot, dark mode | 165/168 | 106/168 | — |
| Screenshot, module < 3 px after scaling | — | 47/192 | 183/192 |
| Screenshot, quiet zone 1 module | 159/164 | 110/164 | — |
| Camera, no blur | 83/99 | 35/99 | 85/99 |
| Camera, blur 1 px | 66/104 | 36/104 | 73/104 |
| Camera, noise σ 20 | 46/175 | 17/175 | — |
| Migration payload, camera | 31/160 | 1/160 | 37/160 |

No decoder returned a wrong text, except `bardecoder` once.

**Fuzzing.** `rqrr` panicked after about 24,000 runs
(`assertion failed: x <= i32::MAX as f64` in `geometry.rs:55`, perspective
mapping of a crafted image). In a release build (`panic = "abort"`) a
crafted QR image would therefore crash the app. `rxing` ran 85,000 inputs
(coverage 5347 edges) without a crash. Five minutes is a smoke test, not
assurance.

**Size and dependencies** (normal dependencies, all targets):

| | `rqrr` (no default features) | `rxing` (features above) |
| --- | --- | --- |
| Lines of Rust | ~5,200 | ~85,500 |
| `unsafe` | none | none |
| License | (MIT OR Apache-2.0) AND ISC | Apache-2.0 |
| Crates pulled in | 6 (`g2p`, `lru`, …) | ~50, among them `regex`, `num`, `chrono` with `clock` (→ `iana-time-zone`, and per target `windows-core`, `core-foundation-sys`, `android_system_properties`, `wasm-bindgen`) |

`rxing` makes `chrono`'s `clock` feature non-optional. Rigel never calls it,
but it links OS time-zone lookups into `rigel-core`, which is meant to have
no OS access. None of these crates is a network crate; `cargo deny` with
today's `deny.toml` accepts them.

## Limitations

- Only synthetic images. No real camera frames or screenshots were used
  (they would contain real accounts, rule 18). Real-device testing belongs
  to the scanner UI epic (E7) and its QA pass.
- The camera simulation has no motion blur, glare or moiré from photographing
  a screen. In the app the scanner tries many frames per second, so the
  per-frame rate matters less than for a single screenshot.
- `bardecoder` was only measured on 256 images; it is clearly behind on both
  sets and fails on dark mode, so it was not pursued.

## Recommendation

Use `rxing` (features `decoders`, `qrcode`, `encoding_rs`; no `image`
feature) behind a small Rust module in `rigel-core`:

1. **Input.** Camera frames arrive as a luma (Y) plane with width and height,
   which every platform camera API provides. Screenshots and image files
   arrive as file bytes; Rust decodes PNG and JPEG with `png` and
   `zune-jpeg` (pure Rust), converting to luma. Size limits first: file
   bytes (20 MiB, existing limit) **and a new limit on pixels**, because a
   small PNG can expand to gigabytes. Proposal: at most 8192 px per side and
   40 megapixels.
2. **Decoding.** `TryHarder` on, then one retry on the inverted image (dark
   mode). The result is text only. It goes to the otpauth parser, or later
   to the Google migration importer (E9).
3. **Conditions.**
   - A fuzz target for the QR entry point in `core/fuzz`, running nightly.
   - `cargo vet` exemptions for the new crates, or trust entries.
   - With the closed crate allowlist of PR #4, every new crate also needs
     an entry there.
   - Optionally, ask upstream to make `chrono` optional in `rxing`, so that
     `rigel-core` stays free of OS calls.
4. **Report the `rqrr` panic upstream** regardless.

Spec changes if accepted (not made in this spike):

- threat-model.md SR-29: name `rxing` instead of "for example `rqrr`".
- backup-format.md section 8 and `limits.rs`: add the pixel limit.
