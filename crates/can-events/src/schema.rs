//! Event schema v1 — the contract between `can` and any orchestrator.
//!
//! Every event type lives in the [`Event`] enum below, so the whole schema
//! is auditable in one screen. Adding an event means adding a variant and
//! its payload struct here; nothing else in the crate needs to change.
//!
//! Serialization shape (see ADR-0010): the variant name becomes the
//! `"event"` field and the payload becomes the `"data"` object.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Schema version stamped on every envelope.
pub const SCHEMA_VERSION: u32 = 1;

/// All events `can` can emit. The serialized form is
/// `{"event":"egress_request","data":{…}}`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum Event {
    /// First event of a run, emitted by the CLI process.
    RunStart(RunStart),
    /// Fully resolved policy plus its canonical hash (ADR-0014).
    PolicyResolved(PolicyResolved),
    /// A command was executed: the sandbox entrypoint, or a supervised
    /// `execve`/`execveat` when argument-level filtering is active.
    ProcessExec(ProcessExec),
    /// An HTTP request reached the proxy and was allowed or blocked.
    EgressRequest(EgressRequest),
    /// A request was refused by its per-destination contract.
    ContractViolation(ContractViolation),
    /// DLP refused (or, in monitor mode, observed) a request or response.
    DlpBlock(DlpBlock),
    /// A canary token was observed leaving the sandbox (ADR-0012).
    CanaryFire(CanaryFire),
    /// A full HTTP exchange through the proxy (ADR-0011).
    Exchange(Exchange),
    /// Periodic counters and latency histogram (ADR-0015).
    Stats(Stats),
    /// Last event of a run, emitted by the CLI process.
    RunEnd(RunEnd),
    /// Closing signature over a stream's hash chain (ADR-0016).
    StreamSeal(StreamSeal),
}

impl Event {
    /// The `"event"` field value for this variant. Useful for logs and
    /// tests that don't want to serialize the whole payload.
    pub fn name(&self) -> &'static str {
        match self {
            Self::RunStart(_) => "run_start",
            Self::PolicyResolved(_) => "policy_resolved",
            Self::ProcessExec(_) => "process_exec",
            Self::EgressRequest(_) => "egress_request",
            Self::ContractViolation(_) => "contract_violation",
            Self::DlpBlock(_) => "dlp_block",
            Self::CanaryFire(_) => "canary_fire",
            Self::Exchange(_) => "exchange",
            Self::Stats(_) => "stats",
            Self::RunEnd(_) => "run_end",
            Self::StreamSeal(_) => "stream_seal",
        }
    }
}

/// Whether the enforcement layer let something through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allowed,
    Blocked,
}

/// Where in a request a detector matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    Header,
    Path,
    Query,
    Body,
    Trailer,
    Response,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunStart {
    /// Version of the `can` binary emitting the stream.
    pub can_version: String,
    /// Command line of the sandboxed workload.
    pub command: Vec<String>,
    /// Sandbox name from `canister.toml`, when the run came from `can up`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<String>,
    pub monitor: bool,
    pub strict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyResolved {
    /// SHA-256 over the canonical serialization of `policy`.
    pub policy_sha256: String,
    /// The fully resolved policy, same content as `can recipe show`.
    pub policy: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProcessExec {
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EgressRequest {
    pub host: String,
    pub method: String,
    pub path: String,
    pub decision: Decision,
    /// Machine-readable reason for a block (`policy`, `contract`, `dlp`,
    /// `dns-entropy`, …). Absent when allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContractViolation {
    pub host: String,
    pub method: String,
    pub path: String,
    /// Reason code from `ContractViolation::reason` in `can-proxy`.
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DlpBlock {
    pub host: String,
    pub detector: String,
    /// Redacted match — the raw secret never enters the stream.
    pub matched_redacted: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// `false` in monitor mode, where the finding is observed but the
    /// request proceeds.
    pub blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CanaryFire {
    pub host: String,
    pub detector: String,
    pub matched_redacted: String,
    /// Data class of the canary (`ahv`, `iban_ch`, …) for externally
    /// supplied canaries; absent for canaries generated by `can` itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_class: Option<String>,
    /// `true` when this destination is allowed to see this data class —
    /// the fire is observational, not a block.
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Exchange {
    pub host: String,
    pub request: ExchangeRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ExchangeResponse>,
    /// Set for protocol upgrades we do not decode (`websocket`), in which
    /// case no frames are captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<String>,
    pub timings: ExchangeTimings,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExchangeRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    #[serde(flatten)]
    pub body: CapturedBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExchangeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(flatten)]
    pub body: CapturedBody,
    /// Chunk boundaries for streamed responses (SSE, chunked transfer),
    /// so a consumer can reconstruct streamed messages in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<BodyChunk>,
}

/// Base64-encoded body plus truncation state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct CapturedBody {
    #[serde(rename = "body_b64", skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
    /// Length of the body before truncation.
    pub body_bytes: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BodyChunk {
    /// Milliseconds after the request started.
    pub offset_ms: u64,
    pub data_b64: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ExchangeTimings {
    pub started_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_byte_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_ms: Option<u64>,
}

/// Cumulative counters since the emitting process started, so a dropped
/// event costs resolution rather than correctness: a consumer diffs
/// consecutive snapshots. Each stream reports what it observes; the proxy
/// stream carries these.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Stats {
    /// Proxied requests keyed by decision (`allowed`, `blocked`).
    pub requests_by_decision: BTreeMap<String, u64>,
    pub contract_violations_by_reason: BTreeMap<String, u64>,
    pub dlp_blocks_by_detector: BTreeMap<String, u64>,
    /// Canary fires keyed by `"<data_class>:<allowed|blocked>"`.
    /// A generated tripwire canary has no class and reports `"-:blocked"`.
    pub canary_fires: BTreeMap<String, u64>,
    pub proxy_latency_ms: Histogram,
}

/// Fixed-bucket latency histogram. Buckets are upper bounds in
/// milliseconds; `counts` has one entry per bucket plus a final
/// `+Inf` entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct Histogram {
    pub buckets_ms: Vec<u64>,
    pub counts: Vec<u64>,
    pub sum_ms: u64,
    pub count: u64,
}

/// Signature over everything a stream emitted (ADR-0016).
///
/// The hash chain proves a stream is internally consistent; it does not
/// say who wrote it, and anyone who can rewrite a line can rewrite the
/// chain along with it. The seal closes that gap: the emitting process
/// signs its final chain head with a key the sandboxed workload never
/// sees, so a consumer can tell "these are the bytes `can` wrote" from
/// "these are bytes someone produced later".
///
/// Signed message, exactly:
///
/// ```text
/// canister-event-stream-v1\n<run_id>\n<stream>\n<events>\n<chain_head>
/// ```
///
/// `events` is the number of events that preceded the seal, and
/// `chain_head` their last `chain_hash` in lowercase hex — so the
/// signature commits to the whole stream, not merely to its last line.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StreamSeal {
    /// Signature algorithm. Only `ed25519` exists today; the field is
    /// present so a verifier refuses what it does not understand rather
    /// than guessing.
    pub algorithm: String,
    /// Verifying key, lowercase hex. A consumer decides which keys it
    /// trusts; the seal only says which one signed.
    pub public_key: String,
    /// Signature over the message above, lowercase hex.
    pub signature: String,
    /// Number of events sealed, excluding the seal itself.
    pub events: u64,
    /// The chain head that was signed, lowercase hex.
    pub chain_head: String,
}

/// Terminal event of a run.
///
/// `exit_code` follows the POSIX `128 + signal` convention that `can`
/// itself applies when the workload is killed by a signal; the raw wait
/// status is not preserved through the supervised PID-namespace path, so
/// no separate `signal` field is reported. `exit_code` is absent when the
/// sandbox failed before the workload ran, in which case `error` says why.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunEnd {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Documentation-only view of one line of the stream, used to generate
/// `docs/events-schema-v1.json`. The runtime writer builds the same
/// shape field by field (see `render_envelope`), with `chain_hash`
/// always last.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Envelope {
    /// Schema version. Always `1` for this document.
    pub schema: u32,
    /// Run identifier, from `--run-id`.
    pub run_id: String,
    /// Emitting process: `cli`, `proxy` or `supervisor`. Each stream has
    /// its own `seq` space and hash chain.
    pub stream: String,
    /// Position within the stream, starting at 0 and incrementing by one.
    pub seq: u64,
    /// Emission time, milliseconds since the Unix epoch.
    pub ts_ms: u64,
    /// `chain_hash` of the previous event in this stream; 64 zeros for
    /// the first event.
    pub prev_hash: String,
    #[serde(flatten)]
    pub event: Event,
    /// `sha256` of this line with the trailing `,"chain_hash":"…"`
    /// removed.
    pub chain_hash: String,
}
