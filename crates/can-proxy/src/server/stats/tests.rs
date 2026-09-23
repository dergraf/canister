//! Unit tests for the stats collector. The collector is process-global,
//! so these tests take a lock and reset it.

use super::*;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn locked() -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    reset();
    guard
}

#[test]
fn requests_are_counted_by_decision() {
    let _guard = locked();

    record_request(Decision::Allowed, 1);
    record_request(Decision::Allowed, 1);
    record_request(Decision::Blocked, 1);

    let stats = snapshot();
    assert_eq!(stats.requests_by_decision["allowed"], 2);
    assert_eq!(stats.requests_by_decision["blocked"], 1);
    assert_eq!(stats.proxy_latency_ms.count, 3);
}

#[test]
fn latencies_land_in_the_documented_buckets() {
    let _guard = locked();

    // One in the first bucket (<=5), one in the third (<=25), one above
    // every bound.
    record_request(Decision::Allowed, 3);
    record_request(Decision::Allowed, 20);
    record_request(Decision::Allowed, 60_000);

    let histogram = snapshot().proxy_latency_ms;
    assert_eq!(histogram.buckets_ms, LATENCY_BUCKETS_MS.to_vec());
    assert_eq!(histogram.counts.len(), LATENCY_BUCKETS_MS.len() + 1);
    assert_eq!(histogram.counts[0], 1, "3ms is in the <=5ms bucket");
    assert_eq!(histogram.counts[2], 1, "20ms is in the <=25ms bucket");
    assert_eq!(
        *histogram.counts.last().expect("inf bucket"),
        1,
        "60s lands in +Inf"
    );
    assert_eq!(histogram.sum_ms, 3 + 20 + 60_000);
    assert_eq!(histogram.count, 3);
}

#[test]
fn a_latency_exactly_on_a_bound_belongs_to_that_bucket() {
    let _guard = locked();

    record_request(Decision::Allowed, 5);
    record_request(Decision::Allowed, 6);

    let histogram = snapshot().proxy_latency_ms;
    assert_eq!(histogram.counts[0], 1, "5ms is <= the 5ms bound");
    assert_eq!(histogram.counts[1], 1, "6ms moves to the next bucket");
}

#[test]
fn the_largest_bound_and_one_above_it_are_separated() {
    let _guard = locked();
    let largest = *LATENCY_BUCKETS_MS.last().expect("bounds");

    record_request(Decision::Allowed, largest);
    record_request(Decision::Allowed, largest + 1);

    let histogram = snapshot().proxy_latency_ms;
    assert_eq!(histogram.counts[LATENCY_BUCKETS_MS.len() - 1], 1);
    assert_eq!(histogram.counts[LATENCY_BUCKETS_MS.len()], 1);
}

#[test]
fn violations_blocks_and_fires_are_keyed_by_cause() {
    let _guard = locked();

    record_contract_violation("method-not-allowed");
    record_contract_violation("method-not-allowed");
    record_contract_violation("path-not-allowed");
    record_dlp_block("canary_token");
    record_canary_fire(Some("ahv"), false);
    record_canary_fire(Some("ahv"), true);
    record_canary_fire(None, false);

    let stats = snapshot();
    assert_eq!(stats.contract_violations_by_reason["method-not-allowed"], 2);
    assert_eq!(stats.contract_violations_by_reason["path-not-allowed"], 1);
    assert_eq!(stats.dlp_blocks_by_detector["canary_token"], 1);
    assert_eq!(stats.canary_fires["ahv:blocked"], 1);
    assert_eq!(stats.canary_fires["ahv:allowed"], 1);
    assert_eq!(stats.canary_fires["-:blocked"], 1, "generated tripwire");
}

#[test]
fn counters_are_cumulative_so_a_consumer_can_diff_snapshots() {
    let _guard = locked();

    record_request(Decision::Allowed, 1);
    let first = snapshot();
    record_request(Decision::Allowed, 1);
    let second = snapshot();

    assert_eq!(first.requests_by_decision["allowed"], 1);
    assert_eq!(second.requests_by_decision["allowed"], 2);
}

#[test]
fn an_untouched_collector_reports_empty_counters() {
    let _guard = locked();

    let stats = snapshot();
    assert!(stats.requests_by_decision.is_empty());
    assert!(stats.canary_fires.is_empty());
    assert_eq!(stats.proxy_latency_ms.count, 0);
    assert_eq!(stats.proxy_latency_ms.sum_ms, 0);
    assert_eq!(
        stats.proxy_latency_ms.counts.len(),
        LATENCY_BUCKETS_MS.len() + 1
    );
}
