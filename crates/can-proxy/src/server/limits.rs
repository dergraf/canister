use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ProxyLimits {
    /// Whole-buffer scan ceiling. Bodies at or under this size get the
    /// full DLP pipeline (decode chain, decompression, unescape, regex).
    pub max_buffered_body_bytes: usize,
    /// Hard cap. Bodies above [`Self::max_buffered_body_bytes`] but at or
    /// under this size are scanned via the chunked streaming primitive
    /// (regex + canary substring, no decode chain). Bodies above this
    /// cap are refused with 413.
    pub max_streamed_body_bytes: usize,
    pub upstream_request_timeout: Duration,
    /// Recipe-supplied upstream scheme override (`http` or `h2c`). When
    /// `None`, the scheme is inferred from the inbound request. See R11.
    pub upstream_scheme: Option<String>,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_buffered_body_bytes:
                can_policy::config::ProxyConfig::DEFAULT_MAX_BUFFERED_BODY_BYTES,
            max_streamed_body_bytes:
                can_policy::config::ProxyConfig::DEFAULT_MAX_STREAMED_BODY_BYTES,
            upstream_request_timeout: Duration::from_millis(
                can_policy::config::ProxyConfig::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_MS,
            ),
            upstream_scheme: None,
        }
    }
}

impl ProxyLimits {
    pub fn from_config(proxy: &can_policy::config::ProxyConfig) -> Self {
        Self {
            max_buffered_body_bytes: proxy.max_buffered_body_bytes(),
            max_streamed_body_bytes: proxy.max_streamed_body_bytes(),
            upstream_request_timeout: proxy.upstream_request_timeout(),
            upstream_scheme: proxy.upstream_scheme().map(str::to_string),
        }
    }
}
