//! Response-direction canary scan. Buffers the upstream response body
//! up to `max_buffered_body_bytes`, looks for any session canary in the
//! bytes, and refuses (451) or passes through accordingly.

use http_body_util::{BodyExt, Limited};
use hyper::Response;
use tracing::warn;

use super::dlp_ctx::DlpCtx;
use super::limits::ProxyLimits;
use super::responses::{ProxyBody, ProxyError};
use super::util::update_content_length;

pub(super) async fn scan_response_for_canaries(
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
            // Response body exceeds the buffer. Fail closed: refuse to
            // forward so a canary-bearing payload can't sneak through
            // by simply being large.
            warn!(
                "DLP: response body from {} exceeded {} bytes — refusing to forward unscanned",
                host, limits.max_buffered_body_bytes
            );
            return ProxyError::body_too_large(host, limits.max_buffered_body_bytes)
                .into_response();
        }
    };
    let bytes = collected.to_bytes();

    for canary in dlp.canaries.iter() {
        if bytes.windows(canary.len()).any(|w| w == canary.as_slice()) {
            warn!(
                "DLP: canary token echoed back from {} — blocking response (len={})",
                host,
                bytes.len()
            );
            // Canaries get their own chain-hashed audit line. Even in
            // monitor mode we still emit the audit record so the
            // orchestrator sees the fire.
            let redacted = can_dlp::redact(std::str::from_utf8(canary).unwrap_or(""));
            crate::events::canary_fire(host, can_dlp::ids::CANARY_TOKEN, &redacted);
            if !dlp.monitor {
                return ProxyError::dlp_blocked(host, can_dlp::ids::CANARY_TOKEN).into_response();
            }
            break;
        }
    }

    let mut rebuilt = Response::from_parts(parts, super::responses::body_from(bytes.clone()));
    update_content_length(rebuilt.headers_mut(), bytes.len());
    rebuilt
}
