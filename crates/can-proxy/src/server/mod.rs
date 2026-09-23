//! L7 proxy. Each submodule owns one concern; this `mod.rs` is the
//! facade that re-exports the public types and threads submodules
//! together.
//!
//! Splitting from the original ~1160-line `server.rs`:
//! - `lifecycle` — `ProxyServer`, `ProxyServerConfig`, `ProxyError`, accept loop.
//! - `limits` — `ProxyLimits`.
//! - `canaries` — external, tagged canaries (ADR-0012).
//! - `capture` — `CaptureCtx`, `ExchangeRecorder` (exchange capture, ADR-0011).
//! - `dlp_ctx` — `DlpCtx`, `DlpCtx::from_config` (R32).
//! - `request` — `handle_proxy_request`, `handle_inner_request` (stage-ified, R31).
//! - `passthrough` — non-MITM forwarding paths.
//! - `tunnel` — TLS MITM tunnel.
//! - `upstream` — connect + forward upstream (http/https/h2c).
//! - `stats` — cumulative counters and latency histogram (ADR-0015).
//! - `stream_scan` — R17 chunked body scan.
//! - `response_scan` — R8 response-direction canary scan.
//! - `dlp_enforce` — verdict → response, plus the shared warn/block/canary-fire helper (R33).
//! - `responses` — unified `ProxyError` builder (replaces five near-identical response constructors, R30).
//! - `util` — pure helpers (host parsing, content-length update).

mod canaries;
mod capture;
mod dlp_ctx;
mod dlp_enforce;
mod lifecycle;
mod limits;
mod passthrough;
mod request;
mod response_scan;
mod responses;
mod secret_swap;
pub(crate) mod stats;
mod stream_scan;
mod tunnel;
mod upstream;
mod util;

pub use lifecycle::{ProxyError, ProxyServer, ProxyServerConfig};
pub use limits::ProxyLimits;
pub use secret_swap::SecretSwap;
