//! Golden-file tests: one recorded line per event type, plus the
//! published JSON Schema.
//!
//! These files are the wire contract (ADR-0010). A diff here means
//! consumers must be updated, so the test fails rather than silently
//! rewriting. Regenerate deliberately with:
//!
//! ```sh
//! UPDATE_GOLDEN=1 cargo test -p can-events --test golden
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use can_events::schema::*;
use can_events::{GENESIS_HASH, StreamId, chain_hash, hex32, render_envelope};

/// Fixed timestamp so golden files are stable.
const TS_MS: u64 = 1_760_000_000_000;

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn assert_golden(name: &str, actual: &str) {
    let path = golden_dir().join(format!("{name}.json"));

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(golden_dir()).expect("create golden dir");
        std::fs::write(&path, actual).expect("write golden file");
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden file {}: {e}\nRegenerate with UPDATE_GOLDEN=1 cargo test -p can-events",
            path.display()
        )
    });
    assert_eq!(
        expected, actual,
        "golden mismatch for {name}; this changes the wire contract"
    );
}

/// One instance of every event type in schema v1. A new variant fails to
/// compile here until it is given a golden file.
fn all_events() -> Vec<(&'static str, Event)> {
    vec![
        (
            "run_start",
            Event::RunStart(RunStart {
                can_version: "0.1.0".to_string(),
                command: vec!["python3".to_string(), "agent/main.py".to_string()],
                sandbox: Some("ci".to_string()),
                monitor: false,
                strict: true,
            }),
        ),
        (
            "policy_resolved",
            Event::PolicyResolved(PolicyResolved {
                policy_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_string(),
                policy: serde_json::json!({"network": {"egress": "proxy-only"}}),
            }),
        ),
        (
            "process_exec",
            Event::ProcessExec(ProcessExec {
                path: "/usr/bin/python3".to_string(),
                argv: vec!["/usr/bin/python3".to_string(), "agent/main.py".to_string()],
                pid: Some(7),
                decision: Decision::Allowed,
                reason: None,
            }),
        ),
        (
            "egress_request",
            Event::EgressRequest(EgressRequest {
                host: "api.anthropic.com".to_string(),
                method: "POST".to_string(),
                path: "/v1/messages".to_string(),
                decision: Decision::Allowed,
                reason: None,
            }),
        ),
        (
            "egress_request_blocked",
            Event::EgressRequest(EgressRequest {
                host: "evil.example.com".to_string(),
                method: "POST".to_string(),
                path: "/collect".to_string(),
                decision: Decision::Blocked,
                reason: Some("policy".to_string()),
            }),
        ),
        (
            "contract_violation",
            Event::ContractViolation(ContractViolation {
                host: "claims.mock.internal".to_string(),
                method: "DELETE".to_string(),
                path: "/claims/42".to_string(),
                reason: "method-not-allowed".to_string(),
                detail: None,
            }),
        ),
        (
            "dlp_block",
            Event::DlpBlock(DlpBlock {
                host: "evil.example.com".to_string(),
                detector: "GithubPat".to_string(),
                matched_redacted: "ghp_•••••beef (len=40)".to_string(),
                location: Some(Location::Body),
                blocked: true,
            }),
        ),
        (
            "canary_fire",
            Event::CanaryFire(CanaryFire {
                host: "medcodes.mock.internal".to_string(),
                detector: "canary_token".to_string(),
                matched_redacted: "CNRY-•••••AHV".to_string(),
                data_class: Some("ahv".to_string()),
                allowed: false,
                location: Some(Location::Body),
            }),
        ),
        (
            "exchange",
            Event::Exchange(Exchange {
                host: "api.anthropic.com".to_string(),
                request: ExchangeRequest {
                    method: "POST".to_string(),
                    url: "https://api.anthropic.com/v1/messages".to_string(),
                    headers: vec![
                        ("content-type".to_string(), "application/json".to_string()),
                        ("x-api-key".to_string(), "[redacted]".to_string()),
                    ],
                    body: CapturedBody {
                        base64: Some("eyJtb2RlbCI6ICJjbGF1ZGUifQ==".to_string()),
                        body_bytes: 21,
                        truncated: false,
                    },
                },
                response: Some(ExchangeResponse {
                    status: 200,
                    headers: vec![("content-type".to_string(), "text/event-stream".to_string())],
                    body: CapturedBody {
                        base64: None,
                        body_bytes: 12,
                        truncated: false,
                    },
                    chunks: vec![BodyChunk {
                        offset_ms: 12,
                        data_b64: "ZGF0YTogaGkK".to_string(),
                    }],
                }),
                upgrade: None,
                timings: ExchangeTimings {
                    started_ms: TS_MS,
                    first_byte_ms: Some(TS_MS + 12),
                    ended_ms: Some(TS_MS + 40),
                },
            }),
        ),
        (
            "stats",
            Event::Stats(Stats {
                requests_by_decision: BTreeMap::from([
                    ("allowed".to_string(), 12),
                    ("blocked".to_string(), 1),
                ]),
                contract_violations_by_reason: BTreeMap::from([(
                    "method-not-allowed".to_string(),
                    1,
                )]),
                dlp_blocks_by_detector: BTreeMap::from([("canary_token".to_string(), 1)]),
                canary_fires: BTreeMap::from([("ahv:blocked".to_string(), 1)]),
                proxy_latency_ms: Histogram {
                    buckets_ms: vec![5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
                    counts: vec![0, 1, 4, 3, 2, 1, 1, 0, 0, 0, 0],
                    sum_ms: 1234,
                    count: 12,
                },
            }),
        ),
        (
            "run_end",
            Event::RunEnd(RunEnd {
                exit_code: Some(0),
                error: None,
                duration_ms: 42_000,
            }),
        ),
        (
            "stream_seal",
            Event::StreamSeal(StreamSeal {
                algorithm: "ed25519".to_string(),
                public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                    .to_string(),
                signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
                            5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                    .to_string(),
                events: 12,
                chain_head: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                    .to_string(),
            }),
        ),
    ]
}

/// The golden set must cover every variant. A new event type makes this
/// fail to compile until it is added above *and* given a golden file,
/// which is the only thing that keeps the published wire contract
/// complete.
#[test]
fn every_variant_has_a_golden() {
    for (name, event) in all_events() {
        let expected = match event {
            Event::RunStart(_) => "run_start",
            Event::PolicyResolved(_) => "policy_resolved",
            Event::ProcessExec(_) => "process_exec",
            Event::EgressRequest(_) => "egress_request",
            Event::ContractViolation(_) => "contract_violation",
            Event::DlpBlock(_) => "dlp_block",
            Event::CanaryFire(_) => "canary_fire",
            Event::Exchange(_) => "exchange",
            Event::Stats(_) => "stats",
            Event::RunEnd(_) => "run_end",
            Event::StreamSeal(_) => "stream_seal",
        };

        // egress_request appears twice: allowed and blocked.
        assert!(
            name.starts_with(expected),
            "golden {name} does not match variant {expected}"
        );
    }

    let names: Vec<&str> = all_events().into_iter().map(|(name, _)| name).collect();

    for variant in [
        "run_start",
        "policy_resolved",
        "process_exec",
        "egress_request",
        "contract_violation",
        "dlp_block",
        "canary_fire",
        "exchange",
        "stats",
        "run_end",
        "stream_seal",
    ] {
        assert!(
            names.iter().any(|name| name.starts_with(variant)),
            "no golden line for {variant}"
        );
    }
}

#[test]
fn every_event_type_matches_its_golden_line() {
    for (name, event) in all_events() {
        let line = render_envelope("r-golden", StreamId::Proxy, 0, TS_MS, &GENESIS_HASH, &event)
            .expect("render");
        assert_golden(name, &line);
    }
}

#[test]
fn golden_lines_carry_a_verifiable_chain_hash() {
    for (name, event) in all_events() {
        let line = render_envelope("r-golden", StreamId::Proxy, 0, TS_MS, &GENESIS_HASH, &event)
            .expect("render");
        let line = line.trim_end();

        let marker = ",\"chain_hash\":\"";
        let at = line.rfind(marker).expect("chain_hash field");
        let body = format!("{}}}", &line[..at]);
        let hash = &line[at + marker.len()..line.len() - 2];

        assert_eq!(
            hash,
            hex32(&chain_hash(body.as_bytes())),
            "chain for {name}"
        );
    }
}

#[test]
fn golden_lines_round_trip_through_the_schema_types() {
    for (name, _) in all_events() {
        let path = golden_dir().join(format!("{name}.json"));
        let Ok(line) = std::fs::read_to_string(&path) else {
            continue; // covered by the golden test above
        };

        let envelope: Envelope =
            serde_json::from_str(line.trim_end()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(envelope.schema, 1);
        assert_eq!(envelope.stream, "proxy");
        assert_eq!(envelope.prev_hash, hex32(&GENESIS_HASH));
    }
}

#[test]
fn published_json_schema_is_up_to_date() {
    let schema = schemars::schema_for!(Envelope);
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(&schema).expect("serialize schema")
    );

    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/events-schema-v1.json")
        .canonicalize()
        .unwrap_or_else(|_| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/events-schema-v1.json")
        });

    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &rendered).expect("write schema");
        return;
    }

    let published = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing {}: {e}\nRegenerate with UPDATE_GOLDEN=1 cargo test -p can-events",
            path.display()
        )
    });
    assert_eq!(
        published, rendered,
        "docs/events-schema-v1.json is stale; regenerate with UPDATE_GOLDEN=1"
    );
}
