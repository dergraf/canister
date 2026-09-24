//! Unified proxy error response builder.
//!
//! Every refusal the proxy returns to the sandboxed worker has the same
//! shape: an HTTP status, a small text body explaining what happened,
//! and at least one `x-canister-error` header so callers can distinguish
//! proxy errors from upstream errors without parsing the body.
//!
//! Prior versions had five almost-identical builder functions
//! (`policy_blocked_response`, `payload_too_large_response`,
//! `gateway_timeout_response`, `dlp_blocked_response`,
//! `dlp_blocked_response_no_event`). This module consolidates them into
//! one type so adding a new error class is a single match arm.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};
use tracing::warn;

pub(super) type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Builder for a proxy-originated HTTP response. Each variant of
/// [`ErrorKind`] fixes the (status, body, error header) triple; the
/// builder fluently adds a DLP detector header and controls whether a
/// structured `dlp_block` event is emitted.
pub(super) struct ProxyError<'a> {
    kind: ErrorKind,
    host: &'a str,
    detector: Option<&'a str>,
    emit_event: bool,
}

#[derive(Clone)]
pub(super) enum ErrorKind {
    /// Connection-gate refusal. Body mentions whether a domain or an
    /// IP literal was rejected.
    PolicyBlocked { reason: &'static str },
    /// Request body exceeded `max_streamed_body_bytes` (or
    /// `max_buffered_body_bytes` on the response side).
    BodyTooLarge { limit: usize },
    /// Upstream did not respond within the timeout.
    GatewayTimeout { timeout: Duration },
    /// DLP detector fired. `detector` (set via `with_detector`) populates
    /// `x-canister-dlp-detector`.
    DlpBlocked,
    /// Upstream returned a transport error (TLS, DNS, connect, …).
    BadGateway { message: String },
    /// Generic 400 for malformed inbound requests we can't even parse.
    BadRequest,
    /// Per-destination contract refusal. Body carries the `[[host]]`
    /// patch the user can paste into `canister.toml` to allow this
    /// exact shape. `reason` populates `x-canister-error`; `detail`
    /// lines populate the body.
    ContractRefused {
        reason: &'static str,
        detail: String,
        patch: String,
    },
}

impl<'a> ProxyError<'a> {
    pub(super) fn new(kind: ErrorKind, host: &'a str) -> Self {
        Self {
            kind,
            host,
            detector: None,
            emit_event: true,
        }
    }

    /// Convenience: a policy-gate refusal for `host`. `reason` is the
    /// short word used in the body and (currently) just affects the
    /// human-readable message — `policy-blocked` is the stable header.
    pub(super) fn policy_blocked(host: &'a str, host_is_ip: bool) -> Self {
        let reason = if host_is_ip { "ip" } else { "domain" };
        Self::new(ErrorKind::PolicyBlocked { reason }, host)
    }

    pub(super) fn body_too_large(host: &'a str, limit: usize) -> Self {
        Self::new(ErrorKind::BodyTooLarge { limit }, host)
    }

    pub(super) fn gateway_timeout(host: &'a str, timeout: Duration) -> Self {
        Self::new(ErrorKind::GatewayTimeout { timeout }, host)
    }

    pub(super) fn dlp_blocked(host: &'a str, detector: &'a str) -> Self {
        Self::new(ErrorKind::DlpBlocked, host).with_detector(detector)
    }

    pub(super) fn bad_gateway(host: &'a str, message: String) -> Self {
        Self::new(ErrorKind::BadGateway { message }, host)
    }

    pub(super) fn bad_request(host: &'a str) -> Self {
        Self::new(ErrorKind::BadRequest, host)
    }

    /// Build a contract refusal from a [`crate::contracts::ContractViolation`].
    /// Generates the actionable `[[host]]` patch from the violation's
    /// detail so the user can paste 3 lines into `canister.toml` to
    /// unblock themselves.
    pub(super) fn contract_refused(
        host: &'a str,
        violation: crate::contracts::ContractViolation,
    ) -> Self {
        use crate::contracts::ContractViolation as V;
        let reason: &'static str = match &violation {
            V::UnknownHost => "unknown-host",
            V::DisallowedMethod { .. } => "method-not-allowed",
            V::DisallowedContentType { .. } => "content-type-not-allowed",
            V::DisallowedPath { .. } => "path-not-allowed",
            V::OversizeBody { .. } => "body-too-large",
        };
        let (detail, patch) = match &violation {
            V::UnknownHost => (
                format!(
                    "No [[host]] block matches {host} and the global contract mode is `strict`."
                ),
                format!(
                    "[[host]]\ndomain = \"{host}\"\n# Add methods / content_types / paths / allow_credentials to tighten."
                ),
            ),
            V::DisallowedMethod { method, allowed } => (
                format!(
                    "{host} does not accept method `{method}`. Allowed: {}.",
                    allowed.join(", ")
                ),
                format!(
                    "[[host]]\ndomain = \"{host}\"\nmethods = [\"{method}\"]   # extends the shipped contract"
                ),
            ),
            V::DisallowedContentType {
                content_type,
                allowed,
            } => (
                format!(
                    "{host} does not accept Content-Type `{content_type}`. Allowed: {}.",
                    allowed.join(", ")
                ),
                format!(
                    "[[host]]\ndomain = \"{host}\"\ncontent_types = [\"{ct}\"]   # extends the shipped contract",
                    ct = content_type.split(';').next().unwrap_or("").trim()
                ),
            ),
            V::DisallowedPath { path, allowed } => (
                format!(
                    "Path `{path}` is not under any allowed prefix for {host}. Allowed prefixes: {}.",
                    allowed.join(", ")
                ),
                format!(
                    "[[host]]\ndomain = \"{host}\"\npaths = [\"{path}\"]   # extends the shipped contract"
                ),
            ),
            V::OversizeBody { size, limit } => (
                format!("Request body is {size} bytes; per-host limit is {limit} bytes."),
                format!(
                    "[[host]]\ndomain = \"{host}\"\nmax_request_bytes = {size}   # raises the cap to fit"
                ),
            ),
        };
        Self::new(
            ErrorKind::ContractRefused {
                reason,
                detail,
                patch,
            },
            host,
        )
    }

    /// Set the DLP detector header. Implies the variant should carry
    /// the `x-canister-dlp-detector` header.
    pub(super) fn with_detector(mut self, detector: &'a str) -> Self {
        self.detector = Some(detector);
        self
    }

    /// Skip the structured-event emission. Use when the caller has
    /// already emitted `events::dlp_block` with full context (matched
    /// text + redaction).
    pub(super) fn no_event(mut self) -> Self {
        self.emit_event = false;
        self
    }

    pub(super) fn into_response(self) -> Response<ProxyBody> {
        let (status, body, header_kind) = match &self.kind {
            ErrorKind::PolicyBlocked { reason } => {
                warn!("policy refusal: {} for {}", reason, self.host);
                (
                    StatusCode::BAD_GATEWAY,
                    format!("Bad Gateway: {reason} not allowed by policy"),
                    "policy-blocked",
                )
            }
            ErrorKind::BodyTooLarge { limit } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("Payload too large: buffered body exceeded {limit} bytes"),
                "body-too-large",
            ),
            ErrorKind::GatewayTimeout { timeout } => (
                StatusCode::GATEWAY_TIMEOUT,
                format!("Gateway Timeout: upstream did not respond within {timeout:?}"),
                "upstream-timeout",
            ),
            ErrorKind::DlpBlocked => {
                let detector = self.detector.unwrap_or("dlp");
                if self.emit_event {
                    // Caller didn't emit an event itself; the body's
                    // ".dlp_blocked()" form gets an empty-redaction event.
                    crate::events::dlp_block(self.host, detector, "", None, true);
                }
                warn!(
                    "DLP blocked request to {}: detector={}",
                    self.host, detector
                );
                (
                    StatusCode::from_u16(451).unwrap_or(StatusCode::FORBIDDEN),
                    format!("Unavailable For Legal Reasons: DLP policy violation ({detector})"),
                    "dlp-blocked",
                )
            }
            ErrorKind::BadGateway { message } => (
                StatusCode::BAD_GATEWAY,
                format!("Bad Gateway: {message}"),
                "upstream-error",
            ),
            ErrorKind::BadRequest => (
                StatusCode::BAD_REQUEST,
                "Bad Request".to_string(),
                "bad-request",
            ),
            ErrorKind::ContractRefused {
                reason,
                detail,
                patch,
            } => {
                warn!(
                    "contract refusal for {}: {} — {}",
                    self.host, reason, detail
                );
                crate::events::legacy_contract_block(self.host, reason);
                let body = format!(
                    "Refused by canister: {detail}\n\
                     \n\
                     To allow this for the current project, append to ./canister.toml:\n\
                     \n    {indented_patch}\n",
                    indented_patch = patch.replace('\n', "\n    "),
                );
                // 415 covers method, content-type, path, and unknown-host;
                // 413 covers oversize body. Both are conventional and
                // map to "the request shape isn't acceptable here."
                let status = if *reason == "body-too-large" {
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    StatusCode::UNSUPPORTED_MEDIA_TYPE
                };
                (status, body, "contract-refused")
            }
        };

        let mut resp = Response::new(body_from(body));
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            HeaderName::from_static("x-canister-error"),
            HeaderValue::from_static(static_str(header_kind)),
        );
        if let Some(det) = self.detector {
            if let Ok(val) = HeaderValue::from_str(det) {
                resp.headers_mut()
                    .insert(HeaderName::from_static("x-canister-dlp-detector"), val);
            }
        }
        resp
    }
}

/// Map an error-kind string to its `'static str` form. We have a closed
/// set of variants here so a `match` is simpler than runtime interning.
fn static_str(kind: &str) -> &'static str {
    match kind {
        "policy-blocked" => "policy-blocked",
        "body-too-large" => "body-too-large",
        "upstream-timeout" => "upstream-timeout",
        "dlp-blocked" => "dlp-blocked",
        "upstream-error" => "upstream-error",
        "bad-request" => "bad-request",
        "contract-refused" => "contract-refused",
        _ => "proxy-error",
    }
}

// ---------------------------------------------------------------------------
// Body builders
// ---------------------------------------------------------------------------

pub(super) fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub(super) fn body_from<T: Into<Bytes>>(chunk: T) -> ProxyBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
