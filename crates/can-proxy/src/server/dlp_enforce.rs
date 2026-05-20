//! DLP enforcement: turn a verdict (or a sequence of verdicts) into
//! either a refuse-response or a "keep going" outcome, while emitting
//! the right log lines and structured events along the way.
//!
//! Both the request-side scanner (`scan_headers` / `scan_uri` /
//! `scan_body`) and the streaming-side scanner share this code.
//! Previously each had its own near-identical block; this helper is the
//! single source of truth.

use tracing::warn;

use can_dlp::{DetectorAction, DetectorId, ScanVerdict};

use super::responses::{ProxyBody, ProxyError};

/// Source of a finding, for log attribution.
#[derive(Clone, Copy)]
pub(super) enum FindingSource {
    /// Whole-buffer regex pass (request headers / URI / body).
    Request,
    /// Whole-buffer regex pass over the upstream's response shape
    /// (response headers + body). Distinct from `Request` so logs and
    /// the `dlp_block` event stream make the direction visible.
    Response,
    /// Chunked regex pass over a body larger than the buffered cap.
    Streaming,
}

impl FindingSource {
    fn label(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::Streaming => "streaming",
        }
    }
}

/// Process a single finding. Logs, emits the structured `dlp_block`
/// event (and a `canary_fire` event when applicable), and decides
/// whether the caller should abort with a 451 response.
///
/// Returns `Some(resp)` when the request must be refused, `None`
/// when the finding was a warning (or monitor mode) and the caller
/// should continue.
pub(super) fn enforce_one(
    detector: DetectorId,
    matched_text: &str,
    host: &str,
    action: DetectorAction,
    monitor: bool,
    source: FindingSource,
) -> Option<hyper::Response<ProxyBody>> {
    let detector_name = detector.as_str();
    let is_canary = detector_name == can_dlp::ids::CANARY_TOKEN;
    let redacted = can_dlp::redact(matched_text);

    match action {
        DetectorAction::Block => {
            let verb = if monitor {
                "finding (monitor)"
            } else {
                "block"
            };
            warn!(
                "DLP {} {}: detector={}, host={}, matched={}",
                source.label(),
                verb,
                detector_name,
                host,
                redacted
            );
            crate::events::dlp_block(host, detector_name, &redacted);
            if is_canary {
                crate::events::canary_fire(host, detector_name, &redacted);
            }
            if monitor {
                None
            } else {
                Some(
                    ProxyError::dlp_blocked(host, detector_name)
                        .no_event()
                        .into_response(),
                )
            }
        }
        DetectorAction::Warn => {
            warn!(
                "DLP {} warning: detector={}, host={}, matched={}",
                source.label(),
                detector_name,
                host,
                redacted
            );
            None
        }
    }
}

/// Drive [`enforce_one`] across a list of verdicts. Returns the first
/// `Block` response, otherwise `None`.
pub(super) fn enforce_request_verdicts(
    verdicts: &[ScanVerdict],
    host: &str,
    monitor: bool,
) -> Option<hyper::Response<ProxyBody>> {
    enforce_verdicts(verdicts, host, monitor, FindingSource::Request)
}

/// Response-direction analogue of [`enforce_request_verdicts`]. Same
/// shape; logs use the `response` label so dashboards can split
/// inbound exfil attempts from upstream leaks.
pub(super) fn enforce_response_verdicts(
    verdicts: &[ScanVerdict],
    host: &str,
    monitor: bool,
) -> Option<hyper::Response<ProxyBody>> {
    enforce_verdicts(verdicts, host, monitor, FindingSource::Response)
}

fn enforce_verdicts(
    verdicts: &[ScanVerdict],
    host: &str,
    monitor: bool,
    source: FindingSource,
) -> Option<hyper::Response<ProxyBody>> {
    for v in verdicts {
        if let Some(resp) =
            enforce_one(v.detector, &v.matched_text, host, v.action, monitor, source)
        {
            return Some(resp);
        }
    }
    None
}
