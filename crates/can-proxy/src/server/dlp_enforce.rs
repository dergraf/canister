//! DLP enforcement: turn a verdict (or a sequence of verdicts) into
//! either a refuse-response or a "keep going" outcome, while emitting
//! the right log lines and structured events along the way.
//!
//! Both the request-side scanner (`scan_headers` / `scan_uri` /
//! `scan_body`) and the streaming-side scanner share this code.
//! Previously each had its own near-identical block; this helper is the
//! single source of truth.

use tracing::warn;

use can_dlp::{DetectorAction, DetectorId, ScanVerdict, extract::StringSource};
use can_events::schema::Location;

use super::dlp_ctx::DlpCtx;
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

/// Process a single finding. Logs, emits the structured events, and
/// decides whether the caller should abort with a 451 response.
///
/// Canaries take a second step: an *external* canary (ADR-0012) carries a
/// data class and a list of destinations allowed to see it. Reaching one
/// of those destinations is expected behavior — recorded as a
/// `canary_fire` with `allowed: true`, and not blocked. Everything else
/// is a leak.
///
/// Returns `Some(resp)` when the request must be refused, `None` when the
/// finding was a warning, an allowed canary, or monitor mode.
pub(super) fn enforce_one(
    ctx: &DlpCtx,
    detector: DetectorId,
    matched_text: &str,
    host: &str,
    action: DetectorAction,
    source: FindingSource,
    location: Option<Location>,
) -> Option<hyper::Response<ProxyBody>> {
    let detector_name = detector.as_str();
    let is_canary = detector_name == can_dlp::ids::CANARY_TOKEN;
    let redacted = can_dlp::redact(matched_text);
    let monitor = ctx.monitor;

    match action {
        DetectorAction::Block => {
            if is_canary {
                let verdict = ctx.external_canaries.classify(matched_text, host);
                crate::events::canary_fire(
                    host,
                    detector_name,
                    &redacted,
                    verdict.data_class.clone(),
                    verdict.allowed,
                    location,
                );

                if verdict.allowed {
                    // This destination is allowed to see this data class:
                    // the fire is evidence of an expected flow, not a leak.
                    tracing::debug!(
                        host,
                        data_class = verdict.data_class.as_deref().unwrap_or("-"),
                        "canary reached an allowed destination"
                    );
                    return None;
                }
            }

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
            crate::events::dlp_block(host, detector_name, &redacted, location, !monitor);

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

/// Map the scanner's fine-grained source onto the event schema's coarse
/// location. Findings without a source fall back to what the scan pass
/// itself implies.
fn location_of(source: Option<&StringSource>, finding_source: FindingSource) -> Option<Location> {
    match source {
        Some(StringSource::HeaderName) | Some(StringSource::HeaderValue { .. }) => {
            Some(Location::Header)
        }
        Some(StringSource::UriPath { .. }) => Some(Location::Path),
        Some(StringSource::UriQueryKey) | Some(StringSource::UriQueryValue { .. }) => {
            Some(Location::Query)
        }
        Some(StringSource::TrailerName) | Some(StringSource::TrailerValue { .. }) => {
            Some(Location::Trailer)
        }
        Some(StringSource::BodyRaw)
        | Some(StringSource::JsonString { .. })
        | Some(StringSource::JsonKey { .. })
        | Some(StringSource::Multipart { .. })
        | Some(StringSource::FormKey)
        | Some(StringSource::FormValue { .. })
        | Some(StringSource::XmlText { .. })
        | Some(StringSource::XmlAttribute { .. }) => Some(Location::Body),
        None => match finding_source {
            FindingSource::Response => Some(Location::Response),
            FindingSource::Streaming => Some(Location::Body),
            FindingSource::Request => None,
        },
    }
}

/// Drive [`enforce_one`] across a list of verdicts. Returns the first
/// `Block` response, otherwise `None`.
pub(super) fn enforce_request_verdicts(
    ctx: &DlpCtx,
    verdicts: &[ScanVerdict],
    host: &str,
) -> Option<hyper::Response<ProxyBody>> {
    enforce_verdicts(ctx, verdicts, host, FindingSource::Request)
}

/// Response-direction analogue of [`enforce_request_verdicts`]. Same
/// shape; logs use the `response` label so dashboards can split
/// inbound exfil attempts from upstream leaks.
pub(super) fn enforce_response_verdicts(
    ctx: &DlpCtx,
    verdicts: &[ScanVerdict],
    host: &str,
) -> Option<hyper::Response<ProxyBody>> {
    enforce_verdicts(ctx, verdicts, host, FindingSource::Response)
}

fn enforce_verdicts(
    ctx: &DlpCtx,
    verdicts: &[ScanVerdict],
    host: &str,
    source: FindingSource,
) -> Option<hyper::Response<ProxyBody>> {
    for v in verdicts {
        if let Some(resp) = enforce_one(
            ctx,
            v.detector,
            &v.matched_text,
            host,
            v.action,
            source,
            location_of(v.source.as_ref(), source),
        ) {
            return Some(resp);
        }
    }
    None
}
