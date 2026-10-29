// SPDX-License-Identifier: GPL-3.0-or-later
//! Decoding of camera frames, PNG and JPEG into grayscale.
//!
//! Hostile input (T8, SR-28): the byte size is checked first, the pixel
//! dimensions are checked from the header before any pixel buffer is
//! allocated, and PNG is converted row by row, so the only large buffer is
//! the grayscale output (at most [`MAX_QR_IMAGE_PIXELS`] bytes). The pixels
//! can show a seed, so the output is zeroed on drop; the decoders' internal
//! scratch buffers are not (accepted: they are freed right after decoding).

use core::fmt;
use std::io::Cursor;

use zeroize::Zeroizing;
use zune_jpeg::JpegDecoder;
use zune_jpeg::zune_core::colorspace::ColorSpace;
use zune_jpeg::zune_core::options::DecoderOptions;

use crate::limits::{MAX_QR_IMAGE_BYTES, MAX_QR_IMAGE_PIXELS, MAX_QR_IMAGE_SIDE};

/// Why an image was rejected. Carries no image content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ImageError {
    /// The file is larger than [`MAX_QR_IMAGE_BYTES`].
    #[error("image file is too large")]
    FileTooLarge,
    /// Zero width or height, a side above [`MAX_QR_IMAGE_SIDE`], or more
    /// pixels than [`MAX_QR_IMAGE_PIXELS`].
    #[error("image dimensions are out of range")]
    Dimensions,
    /// A luma plane shorter than its width, height and row stride say.
    #[error("luma plane does not match its dimensions")]
    PlaneSize,
    /// Neither PNG nor JPEG.
    #[error("unsupported image format")]
    UnsupportedFormat,
    /// The PNG or JPEG data is malformed or uses an unsupported feature.
    #[error("malformed image")]
    Malformed,
}

/// An 8-bit grayscale image within the QR input limits. Rows are stored
/// top to bottom without padding. Zeroed on drop; `Debug` shows only the
/// size.
pub struct LumaImage {
    width: u32,
    height: u32,
    pixels: Zeroizing<Vec<u8>>,
}

impl LumaImage {
    /// Copies a camera luma (Y) plane. `row_stride` is the distance between
    /// the starts of two rows in `plane`, at least `width`.
    pub fn from_luma_plane(
        width: u32,
        height: u32,
        row_stride: usize,
        plane: &[u8],
    ) -> Result<Self, ImageError> {
        let pixel_count = check_dimensions(width, height)?;
        let w = usize::try_from(width).map_err(|_| ImageError::Dimensions)?;
        let h = usize::try_from(height).map_err(|_| ImageError::Dimensions)?;
        if row_stride < w {
            return Err(ImageError::PlaneSize);
        }
        // The last row needs only `width` bytes, not a full stride.
        let needed = h
            .checked_sub(1)
            .and_then(|rows| rows.checked_mul(row_stride))
            .and_then(|n| n.checked_add(w))
            .ok_or(ImageError::PlaneSize)?;
        if plane.len() < needed {
            return Err(ImageError::PlaneSize);
        }
        let mut pixels = Zeroizing::new(Vec::with_capacity(pixel_count));
        for row in plane.chunks(row_stride).take(h) {
            pixels.extend_from_slice(row.get(..w).ok_or(ImageError::PlaneSize)?);
        }
        Ok(Self {
            width,
            height,
            pixels,
        })
    }

    /// Width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// The pixels, `width * height` bytes, row by row.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
}

impl fmt::Debug for LumaImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LumaImage")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

/// Checks the QR input limits and returns the pixel count.
fn check_dimensions(width: u32, height: u32) -> Result<usize, ImageError> {
    if width == 0 || height == 0 || width > MAX_QR_IMAGE_SIDE || height > MAX_QR_IMAGE_SIDE {
        return Err(ImageError::Dimensions);
    }
    let count = u64::from(width)
        .checked_mul(u64::from(height))
        .filter(|&n| n <= MAX_QR_IMAGE_PIXELS)
        .ok_or(ImageError::Dimensions)?;
    usize::try_from(count).map_err(|_| ImageError::Dimensions)
}

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG_SIGNATURE: &[u8] = b"\xff\xd8\xff";

/// Decodes a PNG or JPEG file (screenshot, saved QR image, photo) into
/// grayscale. Transparent pixels are composed over white.
pub fn decode_image_file(bytes: &[u8]) -> Result<LumaImage, ImageError> {
    if bytes.len() > MAX_QR_IMAGE_BYTES {
        return Err(ImageError::FileTooLarge);
    }
    if bytes.starts_with(PNG_SIGNATURE) {
        decode_png(bytes)
    } else if bytes.starts_with(JPEG_SIGNATURE) {
        decode_jpeg(bytes)
    } else {
        Err(ImageError::UnsupportedFormat)
    }
}

fn decode_png(bytes: &[u8]) -> Result<LumaImage, ImageError> {
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    // Read only the header first: `read_info` allocates line buffers sized
    // by the claimed width.
    let header = decoder
        .read_header_info()
        .map_err(|_| ImageError::Malformed)?;
    let (width, height) = header.size();
    let interlaced = header.interlaced;
    let pixel_count = check_dimensions(width, height)?;
    let w = usize::try_from(width).map_err(|_| ImageError::Dimensions)?;
    // Palette and low bit depths expand to 8 bits, 16 bits are stripped.
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().map_err(|_| ImageError::Malformed)?;
    let (color, depth) = reader.output_color_type();
    if depth != png::BitDepth::Eight {
        return Err(ImageError::Malformed);
    }
    let channels = color.samples();
    let row_bytes = w.checked_mul(channels).ok_or(ImageError::Dimensions)?;
    let h = usize::try_from(height).map_err(|_| ImageError::Dimensions)?;
    let mut pixels = Zeroizing::new(Vec::with_capacity(pixel_count));

    if interlaced {
        // Adam7 rows arrive per pass, so deinterlace into one frame buffer.
        // Rare for screenshots; bounded by the pixel limit (at most 4 bytes
        // per pixel).
        let size = reader.output_buffer_size().ok_or(ImageError::Dimensions)?;
        let mut frame = Zeroizing::new(vec![0u8; size]);
        reader
            .next_frame(&mut frame)
            .map_err(|_| ImageError::Malformed)?;
        for row in frame.chunks(row_bytes).take(h) {
            push_luma_row(&mut pixels, row, color)?;
        }
    } else {
        while let Some(row) = reader.next_row().map_err(|_| ImageError::Malformed)? {
            push_luma_row(&mut pixels, row.data(), color)?;
        }
    }
    if pixels.len() != pixel_count {
        return Err(ImageError::Malformed);
    }
    Ok(LumaImage {
        width,
        height,
        pixels,
    })
}

/// Appends one PNG row (8-bit samples) as grayscale.
fn push_luma_row(out: &mut Vec<u8>, row: &[u8], color: png::ColorType) -> Result<(), ImageError> {
    use png::ColorType;
    match color {
        ColorType::Grayscale => out.extend_from_slice(row),
        ColorType::GrayscaleAlpha => {
            out.extend(row.chunks_exact(2).map(|p| match *p {
                [y, a] => over_white(y, a),
                _ => u8::MAX,
            }));
        }
        ColorType::Rgb => {
            out.extend(row.chunks_exact(3).map(|p| match *p {
                [r, g, b] => luma(r, g, b),
                _ => u8::MAX,
            }));
        }
        ColorType::Rgba => {
            out.extend(row.chunks_exact(4).map(|p| match *p {
                [r, g, b, a] => over_white(luma(r, g, b), a),
                _ => u8::MAX,
            }));
        }
        // `normalize_to_color8` expands palettes; anything else is a bug in
        // the decoder or a feature we do not support.
        ColorType::Indexed => return Err(ImageError::Malformed),
    }
    Ok(())
}

/// ITU-R BT.601 luma with integer weights that sum to 256.
fn luma(r: u8, g: u8, b: u8) -> u8 {
    let sum = u32::from(r)
        .saturating_mul(77)
        .saturating_add(u32::from(g).saturating_mul(150))
        .saturating_add(u32::from(b).saturating_mul(29));
    u8::try_from(sum >> 8).unwrap_or(u8::MAX)
}

/// Composes a gray value with alpha over a white background.
fn over_white(y: u8, alpha: u8) -> u8 {
    let a = u32::from(alpha);
    let mixed = u32::from(y)
        .saturating_mul(a)
        .saturating_add(255u32.saturating_mul(255u32.saturating_sub(a)));
    u8::try_from(mixed.checked_div(255).unwrap_or(255)).unwrap_or(u8::MAX)
}

fn decode_jpeg(bytes: &[u8]) -> Result<LumaImage, ImageError> {
    let side = usize::try_from(MAX_QR_IMAGE_SIDE).map_err(|_| ImageError::Dimensions)?;
    let options = DecoderOptions::default()
        .set_max_width(side)
        .set_max_height(side)
        .jpeg_set_out_colorspace(ColorSpace::Luma);
    let mut decoder = JpegDecoder::new_with_options(Cursor::new(bytes), options);
    decoder
        .decode_headers()
        .map_err(|_| ImageError::Malformed)?;
    let info = decoder.info().ok_or(ImageError::Malformed)?;
    let (width, height) = (u32::from(info.width), u32::from(info.height));
    let pixel_count = check_dimensions(width, height)?;
    let pixels = Zeroizing::new(decoder.decode().map_err(|_| ImageError::Malformed)?);
    if pixels.len() != pixel_count {
        return Err(ImageError::Malformed);
    }
    Ok(LumaImage {
        width,
        height,
        pixels,
    })
}

#[cfg(test)]
mod tests {
    use super::super::testdata::{JPEG_GRAY, JPEG_RGB_420, JPEG_RGB_PROGRESSIVE, PNG_ADAM7_GRAY};
    use super::*;
    use proptest::prelude::*;

    fn png_bytes(
        width: u32,
        height: u32,
        color: png::ColorType,
        depth: png::BitDepth,
        data: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, width, height);
            enc.set_color(color);
            enc.set_depth(depth);
            if color == png::ColorType::Indexed {
                enc.set_palette(vec![0, 0, 0, 255, 255, 255]);
            }
            let mut writer = enc.write_header().unwrap();
            writer.write_image_data(data).unwrap();
        }
        out
    }

    /// 4x2 image: left half black, right half white, in the given layout.
    fn half_black(color: png::ColorType) -> Vec<u8> {
        let px: &[u8] = match color {
            png::ColorType::Grayscale => &[0],
            png::ColorType::GrayscaleAlpha => &[0, 255],
            png::ColorType::Rgb => &[0, 0, 0],
            png::ColorType::Rgba => &[0, 0, 0, 255],
            png::ColorType::Indexed => &[0],
        };
        let white: Vec<u8> = match color {
            png::ColorType::Indexed => vec![1],
            _ => px
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    if i == 3 || (color == png::ColorType::GrayscaleAlpha && i == 1) {
                        *v
                    } else {
                        255
                    }
                })
                .collect(),
        };
        let row: Vec<u8> = [px, px, &white, &white].concat();
        [row.clone(), row].concat()
    }

    const EXPECTED_4X2: [u8; 8] = [0, 0, 255, 255, 0, 0, 255, 255];

    #[test]
    fn png_color_types() {
        for color in [
            png::ColorType::Grayscale,
            png::ColorType::GrayscaleAlpha,
            png::ColorType::Rgb,
            png::ColorType::Rgba,
            png::ColorType::Indexed,
        ] {
            {
                let file = png_bytes(4, 2, color, png::BitDepth::Eight, &half_black(color));
                let img = decode_image_file(&file).unwrap();
                assert_eq!((img.width(), img.height()), (4, 2));
                assert_eq!(img.pixels(), EXPECTED_4X2, "{color:?}");
            }
        }
    }

    #[test]
    fn png_bit_depths() {
        // 1-bit grayscale: 0b0011_0000 is black, black, white, white.
        let file = png_bytes(
            4,
            2,
            png::ColorType::Grayscale,
            png::BitDepth::One,
            &[0b0011_0000, 0b0011_0000],
        );
        assert_eq!(decode_image_file(&file).unwrap().pixels(), EXPECTED_4X2);
        // 16-bit grayscale is reduced to its high byte.
        let row = [0u8, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
        let file = png_bytes(
            4,
            2,
            png::ColorType::Grayscale,
            png::BitDepth::Sixteen,
            &[row, row].concat(),
        );
        assert_eq!(decode_image_file(&file).unwrap().pixels(), EXPECTED_4X2);
    }

    #[test]
    fn png_adam7_interlaced() {
        let img = decode_image_file(PNG_ADAM7_GRAY).unwrap();
        assert_eq!((img.width(), img.height()), (8, 8));
        for row in img.pixels().chunks(8) {
            assert_eq!(row, [0, 0, 0, 0, 255, 255, 255, 255]);
        }
    }

    #[test]
    fn png_transparency_is_composed_over_white() {
        // A fully transparent black pixel is white; half transparent is gray.
        let file = png_bytes(
            2,
            1,
            png::ColorType::Rgba,
            png::BitDepth::Eight,
            &[0, 0, 0, 0, 0, 0, 0, 128],
        );
        assert_eq!(decode_image_file(&file).unwrap().pixels(), [255, 127]);
    }

    #[test]
    fn luma_weights() {
        assert_eq!(luma(0, 0, 0), 0);
        assert_eq!(luma(255, 255, 255), 255);
        assert_eq!(luma(255, 0, 0), 76);
        assert_eq!(luma(0, 255, 0), 149);
        assert_eq!(luma(0, 0, 255), 28);
        assert_eq!(over_white(0, 255), 0);
        assert_eq!(over_white(0, 0), 255);
        assert_eq!(over_white(100, 255), 100);
    }

    #[test]
    fn jpeg_variants() {
        for (name, file) in [
            ("gray", JPEG_GRAY),
            ("4:2:0", JPEG_RGB_420),
            ("progressive", JPEG_RGB_PROGRESSIVE),
        ] {
            let img = decode_image_file(file).unwrap();
            assert_eq!((img.width(), img.height()), (16, 8), "{name}");
            // Lossy: the left half is near black, the right half near white.
            for row in img.pixels().chunks(16) {
                assert!(row[..6].iter().all(|&p| p < 40), "{name}: {row:?}");
                assert!(row[10..].iter().all(|&p| p > 215), "{name}: {row:?}");
            }
        }
    }

    #[test]
    fn dimension_limits() {
        assert_eq!(check_dimensions(0, 1), Err(ImageError::Dimensions));
        assert_eq!(check_dimensions(1, 0), Err(ImageError::Dimensions));
        assert_eq!(check_dimensions(1, 1), Ok(1));
        assert_eq!(check_dimensions(MAX_QR_IMAGE_SIDE, 1), Ok(8192));
        assert_eq!(
            check_dimensions(MAX_QR_IMAGE_SIDE + 1, 1),
            Err(ImageError::Dimensions)
        );
        assert_eq!(
            check_dimensions(1, MAX_QR_IMAGE_SIDE + 1),
            Err(ImageError::Dimensions)
        );
        assert_eq!(check_dimensions(8000, 5000), Ok(40_000_000));
        assert_eq!(check_dimensions(8000, 5001), Err(ImageError::Dimensions));
        assert_eq!(
            check_dimensions(u32::MAX, u32::MAX),
            Err(ImageError::Dimensions)
        );
    }

    #[test]
    fn png_bomb_is_rejected_from_the_header() {
        // A valid PNG claiming 100000 x 100000 pixels: rejected before any
        // pixel buffer exists (the data would only be a few bytes).
        let mut file = png_bytes(1, 1, png::ColorType::Grayscale, png::BitDepth::Eight, &[0]);
        // IHDR width and height live at bytes 16..24; the CRC is not
        // recomputed, so also test that a broken header is refused.
        file[16..20].copy_from_slice(&100_000u32.to_be_bytes());
        file[20..24].copy_from_slice(&100_000u32.to_be_bytes());
        assert!(matches!(
            decode_image_file(&file),
            Err(ImageError::Malformed | ImageError::Dimensions)
        ));
        let big = png_bytes(
            MAX_QR_IMAGE_SIDE + 1,
            1,
            png::ColorType::Grayscale,
            png::BitDepth::One,
            &vec![0; 1025],
        );
        assert_eq!(decode_image_file(&big).unwrap_err(), ImageError::Dimensions);
    }

    #[test]
    fn rejects_other_input() {
        assert_eq!(
            decode_image_file(b"").unwrap_err(),
            ImageError::UnsupportedFormat
        );
        assert_eq!(
            decode_image_file(b"GIF89a....").unwrap_err(),
            ImageError::UnsupportedFormat
        );
        assert_eq!(
            decode_image_file(PNG_SIGNATURE).unwrap_err(),
            ImageError::Malformed
        );
        assert_eq!(
            decode_image_file(JPEG_SIGNATURE).unwrap_err(),
            ImageError::Malformed
        );
        let truncated = &JPEG_GRAY[..JPEG_GRAY.len() / 2];
        // A truncated JPEG may decode partially or fail; it must not panic.
        let _ = decode_image_file(truncated);
        let file = png_bytes(
            4,
            2,
            png::ColorType::Grayscale,
            png::BitDepth::Eight,
            &half_black(png::ColorType::Grayscale),
        );
        assert_eq!(
            decode_image_file(&file[..file.len() - 20]).unwrap_err(),
            ImageError::Malformed
        );
        let huge = vec![0u8; MAX_QR_IMAGE_BYTES + 1];
        assert_eq!(
            decode_image_file(&huge).unwrap_err(),
            ImageError::FileTooLarge
        );
    }

    #[test]
    fn luma_planes() {
        // Stride 5 with one padding byte per row; the last row may be short.
        let plane = [1, 2, 3, 4, 99, 5, 6, 7, 8];
        let img = LumaImage::from_luma_plane(4, 2, 5, &plane).unwrap();
        assert_eq!(img.pixels(), [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            LumaImage::from_luma_plane(4, 2, 5, &plane[..8]).unwrap_err(),
            ImageError::PlaneSize
        );
        assert_eq!(
            LumaImage::from_luma_plane(4, 2, 3, &plane).unwrap_err(),
            ImageError::PlaneSize
        );
        assert_eq!(
            LumaImage::from_luma_plane(0, 2, 5, &plane).unwrap_err(),
            ImageError::Dimensions
        );
        assert_eq!(
            LumaImage::from_luma_plane(MAX_QR_IMAGE_SIDE, MAX_QR_IMAGE_SIDE, 8192, &plane)
                .unwrap_err(),
            ImageError::Dimensions
        );
        assert_eq!(
            LumaImage::from_luma_plane(4, 2, usize::MAX, &plane).unwrap_err(),
            ImageError::PlaneSize
        );
    }

    #[test]
    fn debug_shows_only_the_size() {
        let img = LumaImage::from_luma_plane(2, 1, 2, &[42, 43]).unwrap();
        assert_eq!(format!("{img:?}"), "LumaImage { width: 2, height: 1, .. }");
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = decode_image_file(&data);
        }

        #[test]
        fn corrupted_files_never_panic(index in 0usize..633, value in any::<u8>(), which in 0usize..3) {
            let file = [JPEG_GRAY, JPEG_RGB_420, JPEG_RGB_PROGRESSIVE][which];
            let mut data = file.to_vec();
            if let Some(b) = data.get_mut(index) { *b = value; }
            let _ = decode_image_file(&data);
        }

        #[test]
        fn png_roundtrip(width in 1u32..40, height in 1u32..40, seed in any::<u8>()) {
            let n = usize::try_from(width.checked_mul(height).unwrap()).unwrap();
            let data: Vec<u8> = (0..n).map(|i| u8::try_from(i.checked_rem(251).unwrap()).unwrap() ^ seed).collect();
            let file = png_bytes(width, height, png::ColorType::Grayscale, png::BitDepth::Eight, &data);
            let img = decode_image_file(&file).unwrap();
            prop_assert_eq!(img.pixels(), data.as_slice());
        }
    }
}
