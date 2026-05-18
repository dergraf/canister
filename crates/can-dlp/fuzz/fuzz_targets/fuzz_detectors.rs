#![no_main]
//! Fuzz target for `can_dlp::detectors::PatternSet::scan`. The regex
//! engine must not panic on any input, no matter how malformed the
//! UTF-8 representation appears as a string slice.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let ps = can_dlp::detectors::PatternSet::new().unwrap();
    let _ = ps.scan(data);
});
