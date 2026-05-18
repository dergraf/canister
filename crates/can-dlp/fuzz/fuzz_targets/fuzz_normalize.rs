#![no_main]
//! Fuzz target for `can_dlp::normalize::normalize`. No panics on any
//! UTF-8 input. Output length must be ≤ input length (we only strip /
//! map, never expand).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let out = can_dlp::normalize::normalize(data);
    // Every operation in `normalize` is a strip-or-map-to-ASCII; no
    // single char in the output should exceed its input contribution
    // in bytes.
    assert!(
        out.len() <= data.len(),
        "normalize grew input: {} -> {}",
        data.len(),
        out.len()
    );
});
