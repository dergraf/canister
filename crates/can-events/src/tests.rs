//! Unit tests for the event stream. Kept in their own file so the
//! production-path unwrap guard (`ci/check_unwraps.sh`) can skip them
//! wholesale; test code may unwrap freely.

use super::*;
use schema::{Decision, EgressRequest, RunEnd, RunStart};

/// Writer that hands its bytes back to the test.
#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    fn lines(&self) -> Vec<String> {
        let bytes = self.0.lock().expect("buffer lock");
        String::from_utf8(bytes.clone())
            .expect("utf8")
            .lines()
            .map(str::to_string)
            .collect()
    }
}

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("buffer lock").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("broken pipe"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn egress(host: &str) -> Event {
    Event::EgressRequest(EgressRequest {
        host: host.to_string(),
        method: "GET".to_string(),
        path: "/v1/messages".to_string(),
        decision: Decision::Allowed,
        reason: None,
    })
}

fn run_start() -> Event {
    Event::RunStart(RunStart {
        can_version: "0.1.0".to_string(),
        command: vec!["python3".to_string(), "agent.py".to_string()],
        sandbox: Some("ci".to_string()),
        monitor: false,
        strict: true,
    })
}

/// Reproduce a consumer: strip the `chain_hash` suffix and hash the
/// remaining prefix.
fn split_line(line: &str) -> (String, String) {
    let marker = ",\"chain_hash\":\"";
    let at = line.rfind(marker).expect("chain_hash field");
    let body = format!("{}}}", &line[..at]);
    let hash = line[at + marker.len()..line.len() - 2].to_string();
    (body, hash)
}

#[test]
fn envelope_has_expected_fields_and_order() {
    let buf = SharedBuf::default();
    let stream = EventStream::with_writer("r-1", StreamId::Cli, Box::new(buf.clone()));
    stream.emit(&run_start());

    let line = buf.lines().remove(0);
    assert!(line.starts_with(r#"{"schema":1,"run_id":"r-1","stream":"cli","seq":0,"ts_ms":"#));
    assert!(line.contains(r#""event":"run_start""#));
    assert!(line.contains(r#""data":{"can_version":"0.1.0""#));
    assert!(line.ends_with("\"}"), "chain_hash must be the last field");

    let parsed: serde_json::Value = serde_json::from_str(&line).expect("valid JSON");
    assert_eq!(parsed["schema"], 1);
    assert_eq!(parsed["stream"], "cli");
    assert_eq!(parsed["data"]["sandbox"], "ci");
}

#[test]
fn chain_links_events_and_matches_the_hashed_prefix() {
    let buf = SharedBuf::default();
    let stream = EventStream::with_writer("r-1", StreamId::Proxy, Box::new(buf.clone()));
    stream.emit(&egress("api.anthropic.com"));
    stream.emit(&egress("claims.mock.internal"));
    stream.emit(&Event::RunEnd(RunEnd {
        exit_code: Some(0),
        error: None,
        duration_ms: 1234,
    }));

    let lines = buf.lines();
    assert_eq!(lines.len(), 3);

    let mut expected_prev = hex32(&GENESIS_HASH);
    for (i, line) in lines.iter().enumerate() {
        let (body, hash) = split_line(line);
        assert_eq!(
            hash,
            hex32(&chain_hash(body.as_bytes())),
            "line {i} chain_hash must cover the body"
        );

        let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
        assert_eq!(parsed["seq"], i as u64);
        assert_eq!(parsed["prev_hash"], expected_prev);
        expected_prev = hash;
    }
}

#[test]
fn a_removed_line_breaks_the_chain() {
    let buf = SharedBuf::default();
    let stream = EventStream::with_writer("r-1", StreamId::Proxy, Box::new(buf.clone()));
    for host in ["a.example", "b.example", "c.example"] {
        stream.emit(&egress(host));
    }

    let lines = buf.lines();
    let parse = |s: &str| serde_json::from_str::<serde_json::Value>(s).expect("valid JSON");
    let first = parse(&lines[0]);
    let third = parse(&lines[2]);

    // Dropping the middle line is detectable: seq skips and prev_hash
    // no longer matches the surviving predecessor.
    assert_ne!(third["prev_hash"], first["chain_hash"]);
    assert_eq!(third["seq"], 2);
}

#[test]
fn a_dead_writer_stops_emission_without_panicking() {
    let stream = EventStream::with_writer("r-1", StreamId::Cli, Box::new(FailingWriter));
    stream.emit(&egress("a.example"));
    stream.emit(&egress("b.example"));

    assert_eq!(stream.emitted(), 0, "failed writes must not advance seq");
}

#[test]
fn file_target_appends_jsonl() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.jsonl");
    let config = EventConfig {
        target: EventTarget::File(path.clone()),
        run_id: "r-file".to_string(),
        capture: CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: None,
    };

    let stream = EventStream::open(&config, StreamId::Cli).expect("open file stream");
    stream.emit(&run_start());
    drop(stream);

    // A second process opening the same file appends rather than
    // truncating; its stream starts a fresh chain.
    let second = EventStream::open(&config, StreamId::Proxy).expect("reopen file stream");
    second.emit(&egress("api.anthropic.com"));

    let contents = std::fs::read_to_string(&path).expect("read events");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains(r#""stream":"cli""#));
    assert!(lines[1].contains(r#""stream":"proxy""#));
    assert!(lines[1].contains(&format!(r#""prev_hash":"{}""#, hex32(&GENESIS_HASH))));
}

#[test]
fn a_sealed_stream_verifies_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.jsonl");
    let key = SealKey::from_bytes([3u8; 32]);

    let config = EventConfig {
        target: EventTarget::File(path.clone()),
        run_id: "r-sealed".to_string(),
        capture: CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: Some(key.clone()),
    };

    let stream = EventStream::open(&config, StreamId::Cli).expect("open");
    stream.emit(&run_start());
    stream.emit(&egress("api.anthropic.com"));
    stream.seal();

    let contents = std::fs::read_to_string(&path).expect("read");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 3, "the seal is the stream's last line");

    let seal: serde_json::Value = serde_json::from_str(lines[2]).expect("valid JSON");
    assert_eq!(seal["event"], "stream_seal");
    assert_eq!(seal["data"]["events"], 2);

    // The chain head signed must be the previous line's chain_hash, or a
    // consumer cannot tie the signature to the events it read.
    let previous: serde_json::Value = serde_json::from_str(lines[1]).expect("valid JSON");
    assert_eq!(seal["data"]["chain_head"], previous["chain_hash"]);

    seal::verify(
        seal["data"]["algorithm"].as_str().expect("algorithm"),
        seal["data"]["public_key"].as_str().expect("public_key"),
        seal["data"]["signature"].as_str().expect("signature"),
        "r-sealed",
        "cli",
        2,
        seal["data"]["chain_head"].as_str().expect("chain_head"),
    )
    .expect("the seal must verify against the stream as written");

    assert_eq!(
        seal["data"]["public_key"].as_str().expect("public_key"),
        key.public_key_hex()
    );
}

#[test]
fn an_unsigned_stream_emits_no_seal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.jsonl");

    let config = EventConfig {
        target: EventTarget::File(path.clone()),
        run_id: "r-unsigned".to_string(),
        capture: CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: None,
    };

    let stream = EventStream::open(&config, StreamId::Cli).expect("open");
    stream.emit(&run_start());
    stream.seal();

    let contents = std::fs::read_to_string(&path).expect("read");
    assert_eq!(
        contents.lines().count(),
        1,
        "an unsigned seal would look like evidence of authenticity while proving nothing"
    );
}

#[test]
fn sealing_twice_does_not_write_a_second_seal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.jsonl");

    let config = EventConfig {
        target: EventTarget::File(path.clone()),
        run_id: "r-twice".to_string(),
        capture: CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: Some(SealKey::from_bytes([5u8; 32])),
    };

    let stream = EventStream::open(&config, StreamId::Cli).expect("open");
    stream.emit(&run_start());
    stream.seal();
    stream.seal();

    let contents = std::fs::read_to_string(&path).expect("read");
    assert_eq!(contents.matches(r#""event":"stream_seal""#).count(), 1);
}

#[test]
fn a_sealed_stream_emits_nothing_afterwards() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.jsonl");

    let config = EventConfig {
        target: EventTarget::File(path.clone()),
        run_id: "r-closed".to_string(),
        capture: CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: Some(SealKey::from_bytes([6u8; 32])),
    };

    let stream = EventStream::open(&config, StreamId::Cli).expect("open");
    stream.emit(&run_start());
    stream.seal();
    stream.emit(&egress("late.example.com"));

    let contents = std::fs::read_to_string(&path).expect("read");
    assert!(
        !contents.contains("late.example.com"),
        "an event after the seal would be unsigned evidence in a signed stream"
    );
}

#[test]
fn socket_target_round_trips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");

    let config = EventConfig {
        target: EventTarget::Socket(path.clone()),
        run_id: "r-sock".to_string(),
        capture: CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: None,
    };
    let stream = EventStream::open(&config, StreamId::Proxy).expect("connect");
    stream.emit(&egress("api.anthropic.com"));
    drop(stream);

    let (conn, _addr) = listener.accept().expect("accept");
    let mut reader = std::io::BufReader::new(conn);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line).expect("read line");

    let parsed: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON");
    assert_eq!(parsed["run_id"], "r-sock");
    assert_eq!(parsed["event"], "egress_request");
}

#[test]
fn a_connected_socket_bounds_how_long_a_write_may_block() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("events.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");

    let sock = connect_socket(&path).expect("connect");

    assert_eq!(
        sock.write_timeout().expect("timeout readable"),
        Some(WRITE_TIMEOUT),
        "an unbounded write blocks the request path it is emitted from"
    );
}

#[test]
fn a_consumer_that_stops_reading_does_not_block_the_emitter() {
    // The half-alive consumer: still connected, no longer reading. The
    // socket buffer fills and the write would block forever without a
    // timeout. Uses a short one so the test does not wait out the real
    // five seconds; the mechanism is the same.
    let (writer, _reader) = std::os::unix::net::UnixStream::pair().expect("pair");
    writer
        .set_write_timeout(Some(std::time::Duration::from_millis(50)))
        .expect("set timeout");

    let stream = EventStream::with_writer("r-wedged", StreamId::Proxy, Box::new(writer));

    let started = std::time::Instant::now();
    // Enough events to overflow any socket buffer; emission stops as
    // soon as one write times out.
    for _ in 0..100_000 {
        stream.emit(&run_start());
        if !stream.alive() {
            break;
        }
    }
    let elapsed = started.elapsed();

    assert!(
        !stream.alive(),
        "a stream whose writes cannot make progress must be given up for dead"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "emission took {elapsed:?}; a wedged consumer must not hold the emitter"
    );
}

#[test]
fn connecting_to_a_missing_socket_is_a_typed_error() {
    let config = EventConfig {
        target: EventTarget::Socket(PathBuf::from("/nonexistent/can-events.sock")),
        run_id: "r-missing".to_string(),
        capture: CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: None,
    };

    match EventStream::open(&config, StreamId::Cli) {
        Err(EventError::Connect { path, .. }) => {
            assert_eq!(path, PathBuf::from("/nonexistent/can-events.sock"));
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("connecting to a missing socket must fail"),
    }
}

#[test]
fn global_emit_is_a_no_op_until_installed() {
    uninstall();
    assert!(!enabled());
    emit(egress("a.example"));

    let buf = SharedBuf::default();
    install(EventStream::with_writer(
        "r-global",
        StreamId::Cli,
        Box::new(buf.clone()),
    ));
    assert!(enabled());
    emit(egress("b.example"));
    uninstall();
    emit(egress("c.example"));

    let lines = buf.lines();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("b.example"));
}
