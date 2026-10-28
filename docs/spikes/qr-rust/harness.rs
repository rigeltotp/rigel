// SPDX-License-Identifier: GPL-3.0-or-later
//! qr-rust spike harness (not part of the build). Decodes every image of the
//! data set with each decoder setup and prints hit rates per group.
//!
//! Cargo.toml of the throw-away crate:
//!
//! ```toml
//! rqrr = "0.11.0"
//! rxing = { version = "0.9.3", default-features = false, features = ["encoding_rs", "decoders", "qrcode"] }
//! bardecoder = "0.5.0"
//! image = { version = "0.25.10", default-features = false, features = ["png", "jpeg"] }
//! image024 = { package = "image", version = "0.24", default-features = false, features = ["png", "jpeg"] }
//! serde_json = "1"
//! ```
//!
//! Run: `qrspike <data dir>` (writes `fails.txt` next to the data dir).

use std::collections::BTreeMap;
use std::time::Instant;

fn rqrr_decode(luma: &[u8], w: usize, h: usize) -> Vec<String> {
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| luma[y * w + x]);
    img.detect_grids().into_iter().filter_map(|g| g.decode().ok().map(|(_, s)| s)).collect()
}

fn rxing_decode(luma: &[u8], w: usize, h: usize, harder: bool) -> Vec<String> {
    let mut hints = rxing::DecodeHints::default();
    hints.TryHarder = Some(harder);
    rxing::helpers::detect_in_luma_with_hints(luma.to_vec(), w as u32, h as u32, Some(rxing::BarcodeFormat::QR_CODE), &mut hints)
        .map(|r| vec![r.getText().to_owned()])
        .unwrap_or_default()
}

fn bardecoder_decode(img: &image024::DynamicImage) -> Vec<String> {
    let dec = bardecoder::default_decoder();
    dec.decode(img).into_iter().filter_map(Result::ok).collect()
}

fn main() {
    let dir = std::env::args().nth(1).unwrap();
    let manifest: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/manifest.json")).unwrap()).unwrap();
    let decoders = ["rqrr", "rqrr+invert", "rqrr+invert+2x", "rxing", "rxing+harder+invert", "bardecoder"];
    let mut ok: BTreeMap<(String, String, String), (u32, u32)> = BTreeMap::new();
    let mut time: BTreeMap<String, f64> = BTreeMap::new();
    let mut fails: Vec<String> = Vec::new();
    for m in &manifest {
        let file = m["file"].as_str().unwrap();
        let cat = m["cat"].as_str().unwrap().to_owned();
        let kind = m["kind"].as_str().unwrap().to_owned();
        let truth = m["data"].as_str().unwrap();
        let bytes = std::fs::read(format!("{dir}/{file}")).unwrap();
        let t = Instant::now();
        let dynimg = image::load_from_memory(&bytes).unwrap();
        *time.entry("image-decode".into()).or_default() += t.elapsed().as_secs_f64();
        let luma = dynimg.to_luma8();
        let (w, h) = (luma.width() as usize, luma.height() as usize);
        let inv: Vec<u8> = luma.iter().map(|v| 255 - v).collect();
        for d in decoders {
            let t = Instant::now();
            let found = match d {
                "rqrr" => rqrr_decode(&luma, w, h),
                "rqrr+invert" => {
                    let r = rqrr_decode(&luma, w, h);
                    if r.is_empty() { rqrr_decode(&inv, w, h) } else { r }
                }
                "rxing" => rxing_decode(&luma, w, h, false),
                "rqrr+invert+2x" => {
                    let mut r = rqrr_decode(&luma, w, h);
                    if r.is_empty() { r = rqrr_decode(&inv, w, h); }
                    if r.is_empty() && w * h <= 4_000_000 {
                        let big = image::imageops::resize(&luma, (w * 2) as u32, (h * 2) as u32, image::imageops::FilterType::Triangle);
                        r = rqrr_decode(&big, w * 2, h * 2);
                        if r.is_empty() {
                            let binv: Vec<u8> = big.iter().map(|v| 255 - v).collect();
                            r = rqrr_decode(&binv, w * 2, h * 2);
                        }
                    }
                    r
                }
                "rxing+harder+invert" => {
                    let r = rxing_decode(&luma, w, h, true);
                    if r.is_empty() { rxing_decode(&inv, w, h, true) } else { r }
                }
                _ => {
                    // bardecoder is slow and its own decoder; run on every 4th image only
                    if manifest.iter().position(|x| x["file"] == m["file"]).unwrap() % 5 != 0 { continue; }
                    bardecoder_decode(&image024::load_from_memory(&bytes).unwrap())
                }
            };
            *time.entry(d.into()).or_default() += t.elapsed().as_secs_f64();
            let hit = found.iter().any(|s| s == truth);
            let wrong = !found.is_empty() && !hit;
            if wrong { fails.push(format!("WRONG {d} {file}")); }
            for key in [(cat.clone(), "all".to_owned()), (cat.clone(), kind.clone()),
                        (cat.clone(), format!("dark={}", m["dark"])), (cat.clone(), format!("blur={}", m["blur"])),
                        (cat.clone(), format!("module_px<3={}", m["module_px"].as_f64().map(|v| v < 3.0).unwrap_or(false))),
                        (cat.clone(), format!("border={}", m["border"])), (cat.clone(), format!("fmt={}", m["fmt"])),
                        (cat.clone(), format!("ecc={}", m["ecc"])), (cat.clone(), format!("tilt>0.15={}", m["tilt"].as_f64().map(|v| v > 0.15).unwrap_or(false))),
                        (cat.clone(), format!("contrast<0.5={}", m["contrast"].as_f64().map(|v| v < 0.5).unwrap_or(false))),
                        (cat.clone(), format!("noise={}", m["noise"])), (cat.clone(), format!("frac<0.3={}", m["frac"].as_f64().map(|v| v < 0.3).unwrap_or(false)))] {
                let e = ok.entry((key.0, key.1, d.to_owned())).or_default();
                e.1 += 1;
                if hit { e.0 += 1; }
            }
            if !hit { fails.push(format!("MISS {d} {file} {}", m)); }
        }
    }
    for ((cat, group, d), (hit, n)) in &ok {
        println!("{cat:10} {group:18} {d:22} {hit:4}/{n:4} {:5.1}%", 100.0 * *hit as f64 / *n as f64);
    }
    for (d, t) in &time { println!("time {d}: {:.1} s total", t); }
    std::fs::write(format!("{dir}/../fails.txt"), fails.join("\n")).unwrap();
}
