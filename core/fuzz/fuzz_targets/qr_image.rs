// SPDX-License-Identifier: GPL-3.0-or-later
//! Fuzz target for QR image input (`rigel_core::qr`): PNG and JPEG files and
//! raw camera luma planes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rigel_core::limits::MAX_QR_IMAGE_PIXELS;
use rigel_core::qr::{LumaImage, decode_image_file};

fn check(image: &LumaImage) {
    let pixels = u64::from(image.width()) * u64::from(image.height());
    assert!(pixels <= MAX_QR_IMAGE_PIXELS);
    assert_eq!(image.pixels().len() as u64, pixels);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(image) = decode_image_file(data) {
        check(&image);
    }
    // The first four bytes choose width, height and stride of a luma plane.
    if let [w, h, extra, _, plane @ ..] = data {
        let stride = usize::from(*w) + usize::from(*extra);
        let (w, h) = (u32::from(*w), u32::from(*h));
        if let Ok(image) = LumaImage::from_luma_plane(w, h, stride, plane) {
            check(&image);
        }
    }
});
