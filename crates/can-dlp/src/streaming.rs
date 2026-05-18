//! Streaming DLP scan — emit verdicts incrementally as bytes arrive,
//! tracking a small overlap window so signatures that straddle a chunk
//! boundary aren't missed.
//!
//! Today this primitive is used by the proxy's buffered-and-then-scanned
//! path (R17): we buffer the body into one large `Vec<u8>` and call
//! [`StreamingScanner::feed`] in slices. The buffering still applies
//! (`max_streamed_body_bytes`), but the scanner can short-circuit on the
//! first `Block`-action verdict without re-running the regex set over
//! every byte. A future PR can replace the buffering with a true
//! Body-frame-driven forward path; the `StreamingScanner` API is the
//! contract that path will use.
//!
//! Limitations of chunked scanning (vs. the whole-buffer
//! [`DlpScanner::scan_body`] path):
//!
//! - **No decompression**. gzip / zstd / brotli need the full stream;
//!   chunked scans see compressed bytes only, which generally won't match
//!   text regexes. The whole-buffer path remains the right choice when
//!   bodies are smaller than the decompression-eligible cap.
//! - **No multi-layer decoding**. `decode_layers` operates on a whole
//!   buffer (fragment-aware substring search), not a stream.
//!
//! These are acceptable for the streaming path because:
//! - Most exfil attempts ship plaintext bytes through unencoded fields.
//! - Compressed exfil over the limit is rare in practice, and when it
//!   matters the operator can keep `max_buffered_body_bytes` high
//!   enough to capture it.

use std::collections::HashSet;

use crate::detectors::{DetectorId, PatternSet};

/// Maximum signature length we'll preserve across chunk boundaries.
/// Larger overlap = more safety against split signatures, but more CPU
/// per chunk. 256 bytes covers all detector regexes (longest is the SSH
/// "BEGIN" header at ~36 chars; canary tokens are 40 chars; JWT bodies
/// can be longer but the prefix `eyJ` is what we anchor on).
const DEFAULT_OVERLAP_BYTES: usize = 256;

/// Incremental scanner. Feed bytes as they arrive; receive findings as
/// detectors fire. Caller decides whether a finding warrants
/// short-circuiting (e.g., the proxy aborts the upstream request on a
/// `Block`-action verdict).
pub struct StreamingScanner<'a> {
    patterns: &'a PatternSet,
    canaries: &'a [Vec<u8>],
    overlap: Vec<u8>,
    seen_detectors: HashSet<DetectorId>,
    overlap_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct StreamingFinding {
    pub detector: DetectorId,
    pub matched_text: String,
}

impl<'a> StreamingScanner<'a> {
    /// Create a streaming scanner backed by the existing pattern set and
    /// canary list. The scanner borrows both — they're immutable for the
    /// lifetime of the stream.
    pub fn new(patterns: &'a PatternSet, canaries: &'a [Vec<u8>]) -> Self {
        Self::with_overlap(patterns, canaries, DEFAULT_OVERLAP_BYTES)
    }

    pub fn with_overlap(
        patterns: &'a PatternSet,
        canaries: &'a [Vec<u8>],
        overlap_bytes: usize,
    ) -> Self {
        Self {
            patterns,
            canaries,
            overlap: Vec::new(),
            seen_detectors: HashSet::new(),
            overlap_bytes,
        }
    }

    /// Feed the next chunk. Returns any *new* findings — detectors that
    /// have already fired this stream are not repeated. The scanner
    /// internally prepends the last `overlap_bytes` bytes of the previous
    /// chunk so a signature spanning the boundary is still caught.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<StreamingFinding> {
        let mut combined = Vec::with_capacity(self.overlap.len() + chunk.len());
        combined.extend_from_slice(&self.overlap);
        combined.extend_from_slice(chunk);

        let findings = self.scan_buffer(&combined);

        // Save the tail for next chunk. We deliberately overshoot the
        // signature length so we never lose half a token.
        let len = combined.len();
        if len > self.overlap_bytes {
            self.overlap = combined[len - self.overlap_bytes..].to_vec();
        } else {
            self.overlap = combined;
        }

        findings
    }

    fn scan_buffer(&mut self, buf: &[u8]) -> Vec<StreamingFinding> {
        let mut out = Vec::new();

        let canary_id = DetectorId::new(crate::ids::CANARY_TOKEN);
        for canary in self.canaries.iter() {
            if !canary.is_empty()
                && buf.windows(canary.len()).any(|w| w == canary.as_slice())
                && self.seen_detectors.insert(canary_id)
            {
                out.push(StreamingFinding {
                    detector: canary_id,
                    matched_text: String::from_utf8_lossy(canary).into_owned(),
                });
            }
        }

        if let Ok(text) = std::str::from_utf8(buf) {
            for finding in self.patterns.scan(text) {
                if self.seen_detectors.insert(finding.detector) {
                    out.push(StreamingFinding {
                        detector: finding.detector,
                        matched_text: finding.matched_text,
                    });
                }
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_finds_token_in_single_chunk() {
        let ps = PatternSet::new().unwrap();
        let canaries: Vec<Vec<u8>> = Vec::new();
        let mut s = StreamingScanner::new(&ps, &canaries);
        let token = format!("prefix ghp_{} suffix", "A".repeat(36));
        let findings = s.feed(token.as_bytes());
        assert!(findings.iter().any(|f| f.detector.as_str() == "github_pat"));
    }

    #[test]
    fn streaming_finds_token_split_across_chunks() {
        // The whole point of overlap. Token straddles chunk 1 / chunk 2.
        let ps = PatternSet::new().unwrap();
        let canaries: Vec<Vec<u8>> = Vec::new();
        let mut s = StreamingScanner::new(&ps, &canaries);
        let token = format!("ghp_{}", "A".repeat(36));
        // Split at byte 8 (mid-token).
        let (head, tail) = token.split_at(8);
        let first = s.feed(head.as_bytes());
        assert!(first.is_empty(), "head alone shouldn't trigger");
        let second = s.feed(tail.as_bytes());
        assert!(
            second.iter().any(|f| f.detector.as_str() == "github_pat"),
            "token split across chunks should still fire"
        );
    }

    #[test]
    fn streaming_does_not_repeat_detector() {
        let ps = PatternSet::new().unwrap();
        let canaries: Vec<Vec<u8>> = Vec::new();
        let mut s = StreamingScanner::new(&ps, &canaries);
        let token = format!("ghp_{}", "A".repeat(36));
        let first = s.feed(token.as_bytes());
        assert_eq!(first.len(), 1);
        let second = s.feed(token.as_bytes());
        assert!(second.is_empty(), "same detector fires once per stream");
    }

    #[test]
    fn streaming_finds_canary() {
        let ps = PatternSet::new().unwrap();
        let canary = b"ghp_CANARYVALUEHEREXXXXXXXXXXXXXXXXXXXX".to_vec();
        let canaries = vec![canary.clone()];
        let mut s = StreamingScanner::new(&ps, &canaries);
        let body = format!("payload: {}", std::str::from_utf8(&canary).unwrap());
        let findings = s.feed(body.as_bytes());
        assert!(
            findings
                .iter()
                .any(|f| f.detector.as_str() == "canary_token"),
            "canary should fire"
        );
    }

    #[test]
    fn streaming_overlap_window_is_bounded() {
        // After 100 chunks of 1KiB, the scanner's internal overlap
        // buffer must not have grown unbounded. Default overlap is 256.
        let ps = PatternSet::new().unwrap();
        let canaries: Vec<Vec<u8>> = Vec::new();
        let mut s = StreamingScanner::new(&ps, &canaries);
        let chunk = vec![b'.'; 1024];
        for _ in 0..100 {
            let _ = s.feed(&chunk);
        }
        assert!(
            s.overlap.len() <= DEFAULT_OVERLAP_BYTES,
            "overlap grew to {}",
            s.overlap.len()
        );
    }

    #[test]
    fn streaming_short_chunks_aggregate() {
        // Many tiny chunks (one byte at a time) must still find the
        // token. This is the worst case for an overlap-window scanner;
        // make sure no path drops the running buffer.
        let ps = PatternSet::new().unwrap();
        let canaries: Vec<Vec<u8>> = Vec::new();
        let mut s = StreamingScanner::new(&ps, &canaries);
        let token = format!("npm_{}", "B".repeat(36));
        let mut found = false;
        for b in token.bytes() {
            let fs = s.feed(&[b]);
            if fs.iter().any(|f| f.detector.as_str() == "npm_token") {
                found = true;
            }
        }
        assert!(found, "byte-at-a-time stream should still find token");
    }
}
