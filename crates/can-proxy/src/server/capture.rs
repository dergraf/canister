//! Exchange capture (ADR-0011).
//!
//! Records one `exchange` event per HTTP exchange through the proxy:
//! request and response headers, bodies and timings. Off unless
//! `--capture-exchanges` is set, in which case the request is captured
//! **before** the fake→real secret swap, so a real credential is never in
//! the captured buffer to begin with. Redaction on top of that is defense
//! in depth:
//!
//!   * credential-carrying headers become `[redacted]`
//!   * any fake or real secret value is replaced wherever it appears, in
//!     headers and in bodies, both directions
//!
//! Bodies are capped at `--capture-max-bytes` per direction and flagged
//! with `truncated` when cut.

use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use bytes::Bytes;
use can_events::schema::{
    BodyChunk, CapturedBody, Exchange, ExchangeRequest, ExchangeResponse, ExchangeTimings,
};
use hyper::HeaderMap;

use super::secret_swap::SecretSwap;

/// Replacement text for anything that must not leave the proxy.
const REDACTED: &str = "[redacted]";

/// Header names whose values are always replaced, regardless of content.
const REDACTED_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "cookie",
    "set-cookie",
];

/// Capture settings plus the secret values that must never be recorded.
/// Cloned into every request handler; cheap (one `Arc`).
#[derive(Clone)]
pub(super) struct CaptureCtx {
    max_bytes: usize,
    /// Fake and real secret values, longest first so an overlapping pair
    /// cannot leave a fragment behind.
    secrets: Arc<Vec<String>>,
}

impl CaptureCtx {
    /// `None` when capture is disabled, so call sites can skip the work
    /// entirely.
    pub(super) fn from_config(config: &super::ProxyServerConfig) -> Option<Self> {
        let capture = config.capture.as_ref()?;
        if !capture.exchanges {
            return None;
        }

        let mut secrets: Vec<String> = config
            .secret_swaps
            .iter()
            .flat_map(|swap: &SecretSwap| [swap.fake.clone(), swap.real.clone()])
            .filter(|value| !value.is_empty())
            .collect();
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        secrets.dedup();

        Some(Self {
            max_bytes: capture.max_bytes,
            secrets: Arc::new(secrets),
        })
    }

    /// Header pairs with credential headers and secret values redacted.
    /// Values that are not valid UTF-8 are reported as `[redacted]` too —
    /// there is nothing safe and useful to record for them.
    pub(super) fn headers(&self, map: &HeaderMap) -> Vec<(String, String)> {
        map.iter()
            .map(|(name, value)| {
                let name = name.as_str().to_string();
                if REDACTED_HEADERS.contains(&name.as_str()) {
                    return (name, REDACTED.to_string());
                }
                match value.to_str() {
                    Ok(text) => {
                        let scrubbed = self.scrub_text(text);
                        (name, scrubbed)
                    }
                    Err(_) => (name, REDACTED.to_string()),
                }
            })
            .collect()
    }

    /// Base64 the body, truncating at the cap and scrubbing secrets first.
    pub(super) fn body(&self, bytes: &[u8]) -> CapturedBody {
        let scrubbed = self.scrub_bytes(bytes);
        let truncated = scrubbed.len() > self.max_bytes;
        let slice = if truncated {
            &scrubbed[..self.max_bytes]
        } else {
            &scrubbed[..]
        };

        CapturedBody {
            base64: Some(base64::engine::general_purpose::STANDARD.encode(slice)),
            body_bytes: bytes.len(),
            truncated,
        }
    }

    /// A URL may carry a secret in a query parameter; scrub it the same
    /// way as a header value.
    pub(super) fn url(&self, url: &str) -> String {
        self.scrub_text(url)
    }

    pub(super) fn chunk(&self, offset_ms: u64, data: &[u8]) -> BodyChunk {
        let scrubbed = self.scrub_bytes(data);
        BodyChunk {
            offset_ms,
            data_b64: base64::engine::general_purpose::STANDARD.encode(&scrubbed),
        }
    }

    fn scrub_text(&self, text: &str) -> String {
        let mut out = text.to_string();
        for secret in self.secrets.iter() {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), REDACTED);
            }
        }
        out
    }

    fn scrub_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let mut out = bytes.to_vec();
        for secret in self.secrets.iter() {
            out = replace_all(&out, secret.as_bytes(), REDACTED.as_bytes());
        }
        out
    }
}

/// Byte-level `replace`: bodies are not necessarily UTF-8, and a secret
/// embedded in binary content must still be removed.
fn replace_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return haystack.to_vec();
    }

    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// Accumulates one exchange while the pipeline runs.
pub(super) struct ExchangeRecorder {
    ctx: CaptureCtx,
    host: String,
    started: Instant,
    started_ms: u64,
    request: Option<ExchangeRequest>,
    response: Option<ExchangeResponse>,
    first_byte_ms: Option<u64>,
    upgrade: Option<String>,
}

impl ExchangeRecorder {
    pub(super) fn new(ctx: CaptureCtx, host: &str) -> Self {
        Self {
            ctx,
            host: host.to_string(),
            started: Instant::now(),
            started_ms: unix_ms(),
            request: None,
            response: None,
            first_byte_ms: None,
            upgrade: None,
        }
    }

    pub(super) fn ctx(&self) -> &CaptureCtx {
        &self.ctx
    }

    /// Milliseconds since this exchange started; used for chunk offsets.
    pub(super) fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    pub(super) fn record_request(
        &mut self,
        method: &str,
        url: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) {
        self.request = Some(ExchangeRequest {
            method: method.to_string(),
            url: self.ctx.url(url),
            headers: self.ctx.headers(headers),
            body: self.ctx.body(body),
        });
    }

    pub(super) fn record_response(
        &mut self,
        status: u16,
        headers: &HeaderMap,
        body: &[u8],
        chunks: Vec<BodyChunk>,
        first_byte_ms: Option<u64>,
    ) {
        self.first_byte_ms = first_byte_ms.map(|offset| self.started_ms + offset);
        self.response = Some(ExchangeResponse {
            status,
            headers: self.ctx.headers(headers),
            body: self.ctx.body(body),
            chunks,
        });
    }

    pub(super) fn record_upgrade(&mut self, protocol: &str) {
        self.upgrade = Some(protocol.to_string());
    }

    /// Emit the `exchange` event. Consumes the recorder: one event per
    /// exchange, always.
    pub(super) fn emit(self) {
        let Some(request) = self.request else {
            // Nothing to report: the request never reached a stage where
            // its bytes were known (refused at the connect gate, say).
            return;
        };

        let ended_ms = self.started_ms + self.started.elapsed().as_millis() as u64;
        can_events::emit(can_events::Event::Exchange(Exchange {
            host: self.host,
            request,
            response: self.response,
            upgrade: self.upgrade,
            timings: ExchangeTimings {
                started_ms: self.started_ms,
                first_byte_ms: self.first_byte_ms,
                ended_ms: Some(ended_ms),
            },
        }));
    }
}

/// Outcome of reading a body frame by frame with capture enabled.
pub(super) struct CapturedStream {
    pub(super) bytes: Bytes,
    pub(super) chunks: Vec<BodyChunk>,
    /// Offset of the first data frame, relative to the exchange start.
    pub(super) first_byte_ms: Option<u64>,
    pub(super) trailers: Option<HeaderMap>,
}

/// Read a body frame by frame so chunk boundaries and their timing
/// survive (SSE, chunked transfer). Returns `Err(())` when the body
/// exceeds `limit`, matching the fail-closed behavior of the
/// non-capturing path, which refuses to forward an unscanned oversize
/// body.
pub(super) async fn collect_frames<B>(
    body: B,
    limit: usize,
    recorder: &ExchangeRecorder,
) -> Result<CapturedStream, ()>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    use http_body_util::BodyExt;

    let mut body = body;
    let mut bytes = Vec::new();
    let mut chunks = Vec::new();
    let mut first_byte_ms = None;
    let mut trailers = None;

    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            // A broken body is not a capture problem; report what we have
            // to the caller as an overflow-free result and let the normal
            // path surface the transport error.
            break;
        };

        match frame.into_data() {
            Ok(data) => {
                let offset_ms = recorder.elapsed_ms();
                first_byte_ms.get_or_insert(offset_ms);
                if bytes.len() + data.len() > limit {
                    return Err(());
                }
                bytes.extend_from_slice(&data);
                chunks.push(recorder.ctx().chunk(offset_ms, &data));
            }
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
            }
        }
    }

    Ok(CapturedStream {
        bytes: Bytes::from(bytes),
        chunks,
        first_byte_ms,
        trailers,
    })
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
