// SPDX-License-Identifier: GPL-3.0-or-later
//! QR code input (SR-29): images are decoded in Rust, never by platform or
//! online services.
//!
//! This module turns untrusted input into a [`LumaImage`], an 8-bit
//! grayscale image within the limits of `limits.rs`:
//!
//! - camera frames: the luma (Y) plane that every platform camera API
//!   delivers, via [`LumaImage::from_luma_plane`];
//! - screenshots and image files: PNG or JPEG bytes, via
//!   [`decode_image_file`].
//!
//! Locating and reading the QR code in a [`LumaImage`] follows once the
//! decoder is chosen (spike `docs/spikes/qr-rust.md`).

mod image;
#[cfg(test)]
mod testdata;

pub use image::{ImageError, LumaImage, decode_image_file};
