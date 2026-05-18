use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Maximum bytes buffered for DLP body scanning via the full
    /// whole-buffer pipeline (decode chains, decompression, unescape).
    /// Requests at or under this size get the strongest analysis.
    /// Default 8 MiB. Requests above this size up to
    /// [`Self::max_streamed_body_bytes`] are still scanned but via the
    /// chunked streaming path (regex only, no decode chain).
    #[serde(default)]
    pub max_buffered_body_bytes: Option<usize>,

    /// Hard upper bound on request body size. Beyond this, the proxy
    /// returns 413. Defaults to 64 MiB. Requests between
    /// [`Self::max_buffered_body_bytes`] and this cap are scanned by
    /// the streaming detector: regex passes with a 256-byte overlap
    /// window, no decompression / decode chain.
    #[serde(default)]
    pub max_streamed_body_bytes: Option<usize>,

    /// Upstream request total timeout in milliseconds. Defaults to 30 000 ms.
    #[serde(default)]
    pub upstream_request_timeout_ms: Option<u64>,

    /// Force the upstream request scheme. Accepts `"http"` or `"h2c"`.
    /// When unset (the default), the scheme is inferred from the inbound
    /// request URI. Prior versions consulted a client-controlled
    /// `x-canister-upstream-scheme` header for this — that was a footgun
    /// (the sandboxed process picked the proxy's egress protocol) and is
    /// no longer honoured. h2c also requires the `experimental-h2c` build
    /// feature; without it, setting this to `"h2c"` returns an upstream
    /// error.
    #[serde(default)]
    pub upstream_scheme: Option<String>,
}

impl ProxyConfig {
    pub const DEFAULT_MAX_BUFFERED_BODY_BYTES: usize = 8 * 1024 * 1024;
    pub const DEFAULT_MAX_STREAMED_BODY_BYTES: usize = 64 * 1024 * 1024;
    pub const DEFAULT_UPSTREAM_REQUEST_TIMEOUT_MS: u64 = 30_000;

    pub fn max_buffered_body_bytes(&self) -> usize {
        self.max_buffered_body_bytes
            .unwrap_or(Self::DEFAULT_MAX_BUFFERED_BODY_BYTES)
    }

    pub fn max_streamed_body_bytes(&self) -> usize {
        self.max_streamed_body_bytes
            .unwrap_or(Self::DEFAULT_MAX_STREAMED_BODY_BYTES)
    }

    pub fn upstream_request_timeout(&self) -> Duration {
        Duration::from_millis(
            self.upstream_request_timeout_ms
                .unwrap_or(Self::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_MS),
        )
    }

    pub fn upstream_scheme(&self) -> Option<&str> {
        self.upstream_scheme.as_deref()
    }

    pub fn merge(self, overlay: Self) -> Self {
        Self {
            max_buffered_body_bytes: overlay
                .max_buffered_body_bytes
                .or(self.max_buffered_body_bytes),
            max_streamed_body_bytes: overlay
                .max_streamed_body_bytes
                .or(self.max_streamed_body_bytes),
            upstream_request_timeout_ms: overlay
                .upstream_request_timeout_ms
                .or(self.upstream_request_timeout_ms),
            upstream_scheme: overlay.upstream_scheme.or(self.upstream_scheme),
        }
    }
}
