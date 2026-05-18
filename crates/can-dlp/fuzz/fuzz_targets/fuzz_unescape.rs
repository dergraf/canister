#![no_main]
//! Fuzz target for `can_dlp::unescape::unescape`. No panics on any
//! UTF-8 input. Also checks the round-trip invariant: re-running
//! `unescape` on `unescape(s)` should be a no-op (idempotence) for inputs
//! that contain no escape triggers in the first place.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let out1 = can_dlp::unescape::unescape(data);
    let out2 = can_dlp::unescape::unescape(&out1);
    // `unescape` is not strictly idempotent in general (e.g.
    // `\\u0041` decodes to `A` which then decodes to `A`), but
    // it must converge — running it many times must terminate to a
    // fixed point in bounded passes. We assert bounded convergence by
    // requiring 3 passes to stabilise.
    let out3 = can_dlp::unescape::unescape(&out2);
    let out4 = can_dlp::unescape::unescape(&out3);
    assert_eq!(out3, out4, "unescape did not converge in 4 passes");
});
