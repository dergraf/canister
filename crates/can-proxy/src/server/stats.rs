//! Periodic counters and latency histogram (ADR-0015).
//!
//! `can` does not depend on OpenTelemetry: it emits plain counters in the
//! event stream and lets the consumer turn them into metrics. Counters
//! are **cumulative since process start**, so a dropped `stats` event
//! costs resolution, never correctness — a consumer diffs consecutive
//! snapshots.
//!
//! The collector is process-global for the same reason the event stream
//! is: the values are produced deep in the request pipeline and consumed
//! by one periodic task.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use can_events::schema::{Decision, Histogram, Stats};

/// Explicit bucket upper bounds in milliseconds. Fixed rather than
/// configurable so snapshots from different runs are directly
/// comparable; `counts` carries one entry per bucket plus a final
/// `+Inf`.
pub(crate) const LATENCY_BUCKETS_MS: &[u64] = &[5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

#[derive(Default)]
struct Counters {
    requests_by_decision: BTreeMap<String, u64>,
    contract_violations_by_reason: BTreeMap<String, u64>,
    dlp_blocks_by_detector: BTreeMap<String, u64>,
    canary_fires: BTreeMap<String, u64>,
    /// One slot per bucket plus `+Inf`.
    latency_counts: Vec<u64>,
    latency_sum_ms: u64,
}

impl Counters {
    fn new() -> Self {
        Self {
            latency_counts: vec![0; LATENCY_BUCKETS_MS.len() + 1],
            ..Self::default()
        }
    }

    fn observe_latency(&mut self, ms: u64) {
        let index = LATENCY_BUCKETS_MS
            .iter()
            .position(|bound| ms <= *bound)
            .unwrap_or(LATENCY_BUCKETS_MS.len());
        self.latency_counts[index] += 1;
        self.latency_sum_ms += ms;
    }
}

static COUNTERS: Mutex<Option<Counters>> = Mutex::new(None);
static REQUESTS: AtomicU64 = AtomicU64::new(0);

fn with_counters<R>(f: impl FnOnce(&mut Counters) -> R) -> R {
    // SAFETY-UNWRAP: only counter arithmetic runs under this lock, so a
    // poisoned lock means a panic elsewhere; recovering keeps statistics
    // best-effort rather than propagating a failure into the data path.
    let mut guard = match COUNTERS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    f(guard.get_or_insert_with(Counters::new))
}

pub(crate) fn record_request(decision: Decision, latency_ms: u64) {
    let key = match decision {
        Decision::Allowed => "allowed",
        Decision::Blocked => "blocked",
    };
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    with_counters(|c| {
        *c.requests_by_decision.entry(key.to_string()).or_insert(0) += 1;
        c.observe_latency(latency_ms);
    });
}

pub(crate) fn record_contract_violation(reason: &str) {
    with_counters(|c| {
        *c.contract_violations_by_reason
            .entry(reason.to_string())
            .or_insert(0) += 1;
    });
}

pub(crate) fn record_dlp_block(detector: &str) {
    with_counters(|c| {
        *c.dlp_blocks_by_detector
            .entry(detector.to_string())
            .or_insert(0) += 1;
    });
}

/// Canary fires are keyed by `"<data_class>:<allowed|blocked>"` so one
/// counter answers both "which classes moved" and "which of those were
/// leaks". Generated tripwire canaries have no class and report
/// `"-:blocked"`.
pub(crate) fn record_canary_fire(data_class: Option<&str>, allowed: bool) {
    let key = format!(
        "{}:{}",
        data_class.unwrap_or("-"),
        if allowed { "allowed" } else { "blocked" }
    );
    with_counters(|c| {
        *c.canary_fires.entry(key).or_insert(0) += 1;
    });
}

/// Cumulative snapshot of everything observed so far.
pub(crate) fn snapshot() -> Stats {
    with_counters(|c| Stats {
        requests_by_decision: c.requests_by_decision.clone(),
        contract_violations_by_reason: c.contract_violations_by_reason.clone(),
        dlp_blocks_by_detector: c.dlp_blocks_by_detector.clone(),
        canary_fires: c.canary_fires.clone(),
        proxy_latency_ms: Histogram {
            buckets_ms: LATENCY_BUCKETS_MS.to_vec(),
            counts: c.latency_counts.clone(),
            sum_ms: c.latency_sum_ms,
            count: c.latency_counts.iter().sum(),
        },
    })
}

/// Emit one `stats` event. A no-op without an installed event stream.
pub(crate) fn emit_snapshot() {
    if !can_events::enabled() {
        return;
    }
    can_events::emit(can_events::Event::Stats(snapshot()));
}

/// Reset every counter. Tests only; the collector is process-global.
#[cfg(test)]
pub(crate) fn reset() {
    let mut guard = match COUNTERS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    *guard = Some(Counters::new());
    REQUESTS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests;
