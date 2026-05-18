#![no_main]
//! Full-pipeline fuzz target: feeds arbitrary bytes through the request
//! body scanning path that the proxy uses in production. Catches
//! interactions between decode → normalize → unescape → regex that
//! individual targets miss.

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let scanner = can_dlp::DlpScanner::new(
        Vec::new(),
        &HashMap::new(),
        32,
        true,
        false,
    )
    .expect("scanner init");

    // No panics — that's the whole bar. We don't assert on verdicts;
    // any output the scanner produces from any input is legal.
    let _ = scanner.scan_body(data, None, "fuzz.example.com");
    let _ = scanner.scan_body(data, Some("gzip"), "fuzz.example.com");
    let _ = scanner.scan_body(data, Some("zstd"), "fuzz.example.com");
    let _ = scanner.scan_body(data, Some("br"), "fuzz.example.com");

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = scanner.scan_uri(s, "fuzz.example.com");
        let header_pairs = vec![("Authorization".to_string(), s.to_string())];
        let _ = scanner.scan_headers(&header_pairs, "fuzz.example.com");
    }
});
