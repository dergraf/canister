//! R17 streaming body scan. Feeds the body to `StreamingScanner` in
//! 64 KiB slices; short-circuits the first time a `Block`-action
//! detector fires. Used when the body is larger than
//! `max_buffered_body_bytes` but smaller than `max_streamed_body_bytes`.
//!
//! Decompression is still skipped (needs the full stream), but the
//! fragment-aware decoder now runs per chunk — see `can_dlp::streaming`.

use hyper::Response;

use super::dlp_enforce::{FindingSource, enforce_one};
use super::responses::ProxyBody;

pub(super) fn stream_scan_body(
    scanner: &can_dlp::DlpScanner,
    bytes: &[u8],
    host: &str,
    canaries: &[Vec<u8>],
    monitor: bool,
    max_decode_depth: usize,
) -> Option<Response<ProxyBody>> {
    const CHUNK: usize = 64 * 1024;
    let mut s =
        can_dlp::streaming::StreamingScanner::new(scanner.patterns(), canaries, max_decode_depth);
    for chunk in bytes.chunks(CHUNK) {
        for finding in s.feed(chunk) {
            let action = scanner.streaming_verdict(finding.detector, host);
            if let Some(resp) = enforce_one(
                finding.detector,
                &finding.matched_text,
                host,
                action,
                monitor,
                FindingSource::Streaming,
            ) {
                return Some(resp);
            }
        }
    }
    None
}
