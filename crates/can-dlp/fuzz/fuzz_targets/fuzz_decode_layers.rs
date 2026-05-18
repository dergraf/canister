#![no_main]
//! Fuzz target for `can_dlp::decode::decode_layers`.
//!
//! Goals:
//! - No panics on any input.
//! - Layer count is bounded — the BFS + dedup-by-fingerprint must terminate
//!   even on pathological inputs that try to decode to themselves or
//!   produce alternating chains.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let layers = can_dlp::decode::decode_layers(data, 32);
    // The decode module hard-caps total layers at MAX_TOTAL_LAYERS (256).
    // If a fuzzer-found input ever exceeds that, the cap is broken.
    assert!(layers.len() <= 256, "layer count exceeded cap: {}", layers.len());
    // The original input must always be the first layer.
    if !layers.is_empty() {
        assert_eq!(layers[0], data);
    }
});
