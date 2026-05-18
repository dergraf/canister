use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// Sink for DLP events. Production code writes to stderr; tests substitute
/// an in-memory buffer.
pub trait EventSink: Send + Sync {
    fn emit(&self, line: &[u8]);
}

struct StderrSink;

impl EventSink for StderrSink {
    fn emit(&self, line: &[u8]) {
        // Best-effort. A failed stderr write is itself a real problem,
        // but the proxy has no recovery path — log and move on.
        let _ = std::io::stderr().write_all(line);
        let _ = std::io::stderr().write_all(b"\n");
        let _ = std::io::stderr().flush();
    }
}

static SINK: Mutex<Option<Box<dyn EventSink>>> = Mutex::new(None);

/// Replace the default stderr sink. Used by tests to capture events.
pub fn set_sink_for_test(sink: Box<dyn EventSink>) {
    let mut guard = SINK.lock().expect("event sink mutex poisoned");
    *guard = Some(sink);
}

fn emit(line: String) {
    let bytes = line.into_bytes();
    let guard = SINK.lock().expect("event sink mutex poisoned");
    match guard.as_ref() {
        Some(sink) => sink.emit(&bytes),
        None => StderrSink.emit(&bytes),
    }
}

/// Emit a structured `dlp_block` event for a refused request.
///
/// The line goes to stderr (or the test sink) as compact JSON so a
/// wrapping orchestrator can grep / parse without dealing with the
/// human-readable `warn!` log format. `matched_redacted` is the output of
/// `can_dlp::redact`; the raw token never appears.
pub fn dlp_block(host: &str, detector: &str, matched_redacted: &str) {
    let payload = serde_json::json!({
        "event": "dlp_block",
        "host": host,
        "detector": detector,
        "matched_redacted": matched_redacted,
        "timestamp_ms": unix_ms(),
    });
    emit(payload.to_string());
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// R18: tamper-evident canary fire log
//
// Each `canary_fire` event includes `prev_hash` and `chain_hash`. The chain
// hash is `sha256(prev_hash || serialized_event_body)`. An orchestrator
// reading the log can detect truncation: if any single line is removed or
// reordered, the next line's `prev_hash` will not equal the previous line's
// `chain_hash`.
//
// This is not crypto-strong tamper *resistance* — an attacker who controls
// the proxy process can rewrite the chain — but it does catch passive
// log-shipping corruption and "the SIEM dropped one record" classes of
// failure that would otherwise hide a canary fire.
// ---------------------------------------------------------------------------

static CHAIN_HASH: Mutex<[u8; 32]> = Mutex::new([0u8; 32]);
static CANARY_FIRES: AtomicU64 = AtomicU64::new(0);

/// Emit a `canary_fire` event. Use this *in addition to* `dlp_block` when
/// the detector that fired is a canary (`CanaryToken`). Canary fires are
/// uniquely valuable — by construction the value did not exist outside
/// the sandbox, so any echo is an exfiltration attempt with zero false
/// positives.
pub fn canary_fire(host: &str, detector: &str, matched_redacted: &str) {
    let ts = unix_ms();

    let prev_hash = {
        let guard = CHAIN_HASH.lock().expect("chain hash mutex poisoned");
        *guard
    };
    let new_hash = compute_chain_hash(&prev_hash, host, detector, matched_redacted, ts);
    {
        let mut guard = CHAIN_HASH.lock().expect("chain hash mutex poisoned");
        *guard = new_hash;
    }
    CANARY_FIRES.fetch_add(1, Ordering::Relaxed);

    let payload = serde_json::json!({
        "event": "canary_fire",
        "host": host,
        "detector": detector,
        "matched_redacted": matched_redacted,
        "timestamp_ms": ts,
        "prev_hash": hex32(&prev_hash),
        "chain_hash": hex32(&new_hash),
    });
    emit(payload.to_string());
}

/// Total number of canary fires observed in this process so far. Surfaces
/// in the `can` exit summary so the user sees a non-zero count after a run
/// where any worker tried to exfiltrate a canary.
pub fn canary_fire_count() -> u64 {
    CANARY_FIRES.load(Ordering::Relaxed)
}

fn compute_chain_hash(
    prev: &[u8; 32],
    host: &str,
    detector: &str,
    matched_redacted: &str,
    ts: u128,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    // Zero-byte separators so different fields can't be concatenated
    // ambiguously (`a||b` vs `ab` collisions).
    h.update(b"\0");
    h.update(host.as_bytes());
    h.update(b"\0");
    h.update(detector.as_bytes());
    h.update(b"\0");
    h.update(matched_redacted.as_bytes());
    h.update(b"\0");
    h.update(ts.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Reset the canary fire counter and chain hash. Tests only.
#[cfg(test)]
pub(crate) fn reset_canary_chain_for_test() {
    *CHAIN_HASH.lock().unwrap() = [0u8; 32];
    CANARY_FIRES.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Events use static state (sink, chain hash, counter). Tests must run
    // serially within this module — `cargo test` parallelises by default
    // and the static state races otherwise.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct VecSink(Mutex<Vec<String>>);

    impl EventSink for VecSink {
        fn emit(&self, line: &[u8]) {
            let s = std::str::from_utf8(line).unwrap().to_string();
            self.0.lock().unwrap().push(s);
        }
    }

    #[test]
    fn canary_fire_chain_is_well_formed() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let sink = std::sync::Arc::new(VecSink(Mutex::new(Vec::new())));
        struct Adapter(std::sync::Arc<VecSink>);
        impl EventSink for Adapter {
            fn emit(&self, line: &[u8]) {
                self.0.emit(line);
            }
        }
        set_sink_for_test(Box::new(Adapter(sink.clone())));
        reset_canary_chain_for_test();

        canary_fire("evil.example.com", "CanaryToken", "ghp_•••••1");
        canary_fire("evil.example.com", "CanaryToken", "ghp_•••••2");
        canary_fire("other.example.com", "CanaryToken", "npm_•••••3");

        let lines = sink.0.lock().unwrap().clone();
        assert_eq!(lines.len(), 3);

        let parse = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        let a = parse(&lines[0]);
        let b = parse(&lines[1]);
        let c = parse(&lines[2]);

        // Genesis: first event's prev_hash is all-zero.
        assert_eq!(a["prev_hash"].as_str().unwrap(), "0".repeat(64));

        // Each subsequent event's prev_hash equals the previous event's
        // chain_hash. This is the property that lets an orchestrator
        // notice line drops / reordering.
        assert_eq!(b["prev_hash"], a["chain_hash"]);
        assert_eq!(c["prev_hash"], b["chain_hash"]);

        // chain_hash is 64 hex chars (sha256).
        for evt in [&a, &b, &c] {
            let ch = evt["chain_hash"].as_str().unwrap();
            assert_eq!(ch.len(), 64);
            assert!(ch.bytes().all(|b| b.is_ascii_hexdigit()));
        }

        assert_eq!(canary_fire_count(), 3);

        // Cleanup for other tests.
        let mut guard = SINK.lock().unwrap();
        *guard = None;
        reset_canary_chain_for_test();
    }

    #[test]
    fn dlp_block_emits_structured_event() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let sink = std::sync::Arc::new(VecSink(Mutex::new(Vec::new())));

        struct Adapter(std::sync::Arc<VecSink>);
        impl EventSink for Adapter {
            fn emit(&self, line: &[u8]) {
                self.0.emit(line);
            }
        }

        set_sink_for_test(Box::new(Adapter(sink.clone())));
        dlp_block(
            "evil.example.com",
            "GithubPat",
            "ghp_•••••deadbeef (len=40)",
        );
        let lines = sink.0.lock().unwrap().clone();
        assert_eq!(lines.len(), 1, "expected one event");
        let parsed: serde_json::Value =
            serde_json::from_str(&lines[0]).expect("event must be JSON");
        assert_eq!(parsed["event"], "dlp_block");
        assert_eq!(parsed["host"], "evil.example.com");
        assert_eq!(parsed["detector"], "GithubPat");
        assert!(
            parsed["matched_redacted"]
                .as_str()
                .unwrap()
                .starts_with("ghp_")
        );
        assert!(parsed["timestamp_ms"].is_number());

        // Restore default sink (other tests in the same process).
        let mut guard = SINK.lock().unwrap();
        *guard = None;
    }
}
