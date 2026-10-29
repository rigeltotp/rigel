// SPDX-License-Identifier: GPL-3.0-or-later
//! Size limits for untrusted input.
//!
//! Every parser checks these limits before it allocates or decodes. The values
//! are normative and defined in `docs/specs/backup-format.md`, section
//! "Limits"; keep both in sync.

/// Largest import or backup file the app accepts, in bytes (16 MiB).
pub const MAX_IMPORT_FILE_BYTES: usize = 16 * 1024 * 1024;

/// Largest image passed to the QR decoder, in bytes (20 MiB).
pub const MAX_QR_IMAGE_BYTES: usize = 20 * 1024 * 1024;

/// Longest side of an image passed to the QR decoder, in pixels.
pub const MAX_QR_IMAGE_SIDE: u32 = 8192;

/// Most pixels of an image passed to the QR decoder (40 megapixels). Checked
/// from the image header, so a small file cannot expand into a huge buffer.
pub const MAX_QR_IMAGE_PIXELS: u64 = 40_000_000;

/// Most entries in one vault, backup or import.
pub const MAX_ENTRIES: usize = 10_000;

/// Longest otpauth URI, in bytes.
pub const MAX_OTPAUTH_URI_BYTES: usize = 4096;

/// Shortest and longest decoded OTP secret, in bytes.
pub const MIN_SECRET_BYTES: usize = 1;
/// See [`MIN_SECRET_BYTES`].
pub const MAX_SECRET_BYTES: usize = 256;

/// Longest issuer or account name, in bytes of UTF-8.
pub const MAX_LABEL_BYTES: usize = 256;

/// Longest note, in bytes of UTF-8.
pub const MAX_NOTE_BYTES: usize = 4096;

/// Most tags, websites or app IDs per entry.
pub const MAX_LIST_ITEMS: usize = 64;

/// Deepest JSON nesting a parser accepts.
pub const MAX_JSON_DEPTH: usize = 16;

// Compile-time consistency checks.
const _: () = {
    assert!(MIN_SECRET_BYTES >= 1);
    assert!(MIN_SECRET_BYTES <= MAX_SECRET_BYTES);
    assert!(MAX_OTPAUTH_URI_BYTES < MAX_IMPORT_FILE_BYTES);
    assert!(MAX_QR_IMAGE_PIXELS <= (MAX_QR_IMAGE_SIDE as u64) * (MAX_QR_IMAGE_SIDE as u64));
    // Every entry at a typical size must fit into one import file, otherwise
    // MAX_ENTRIES would be unreachable and misleading.
    assert!(MAX_ENTRIES * 512 <= MAX_IMPORT_FILE_BYTES);
};
