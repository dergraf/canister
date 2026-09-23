//! Exchange capture (ADR-0011) through a real proxy.
//!
//! The load-bearing assertion is negative: a real swapped secret must
//! never appear in a captured exchange, in either direction.

use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use can_policy::config::{EgressMode, HostBlock, NetworkConfig};
use can_proxy::ca::DynamicCa;
use can_proxy::server::{ProxyServer, ProxyServerConfig, SecretSwap};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reqwest::{Client, Proxy};
use tokio::net::TcpListener;

/// The event stream is process-global, so capture tests must not run
/// concurrently with each other. An async mutex, because the guard is
/// held across awaits for the whole test.
static STREAM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const FAKE_SECRET: &str = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const REAL_SECRET: &str = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

struct SocketReader {
    handle: std::thread::JoinHandle<Vec<String>>,
}

impl SocketReader {
    fn listen(path: &std::path::Path) -> Self {
        let listener = std::os::unix::net::UnixListener::bind(path).expect("bind event socket");
        let handle = std::thread::spawn(move || {
            let (conn, _addr) = listener.accept().expect("accept");
            std::io::BufReader::new(conn)
                .lines()
                .map_while(Result::ok)
                .collect()
        });
        Self { handle }
    }

    fn finish(self) -> (Vec<serde_json::Value>, String) {
        can_events::uninstall();
        let lines = self.handle.join().expect("reader thread");
        let raw = lines.join("\n");
        let events = lines
            .iter()
            .map(|line| serde_json::from_str(line).expect("event line must be JSON"))
            .collect();
        (events, raw)
    }
}

/// Upstream that echoes the request body, and streams an SSE response on
/// `/stream` so chunk boundaries have something to preserve.
async fn start_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let streaming = req.uri().path() == "/stream";
                    let bytes = req.into_body().collect().await.expect("body").to_bytes();

                    if streaming {
                        let chunks: Vec<Result<Frame<bytes::Bytes>, hyper::Error>> = vec![
                            Ok(Frame::data(bytes::Bytes::from_static(b"data: one\n\n"))),
                            Ok(Frame::data(bytes::Bytes::from_static(b"data: two\n\n"))),
                            Ok(Frame::data(bytes::Bytes::from_static(b"data: [DONE]\n\n"))),
                        ];
                        let body = StreamBody::new(futures_util::stream::iter(chunks));
                        return Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "text/event-stream")
                                .body(body.boxed())
                                .expect("response"),
                        );
                    }

                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(bytes).map_err(|never| match never {}).boxed())
                            .expect("response"),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    addr
}

async fn start_proxy(capture: can_events::CaptureConfig) -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().expect("ca"));
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_ips: vec!["127.0.0.1".to_string()],
        ..Default::default()
    };
    let hosts = vec![HostBlock {
        domain: "127.0.0.1".to_string(),
        allow_credentials: vec!["github_pat".to_string()],
        ..Default::default()
    }];
    let config = ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts)
        .with_secret_swaps(vec![SecretSwap {
            fake: FAKE_SECRET.to_string(),
            real: REAL_SECRET.to_string(),
            detector: "github_pat".to_string(),
        }])
        .with_capture(capture);
    let proxy = ProxyServer::new(config).expect("proxy");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = proxy.run(listener).await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    addr
}

fn client(proxy_addr: SocketAddr) -> Client {
    Client::builder()
        .proxy(Proxy::all(format!("http://{proxy_addr}")).expect("proxy url"))
        .build()
        .expect("client")
}

fn install_stream(path: &std::path::Path, capture: can_events::CaptureConfig) {
    let config = can_events::EventConfig {
        target: can_events::EventTarget::Socket(path.to_path_buf()),
        run_id: "r-capture".to_string(),
        capture,
        stats_interval_ms: None,
        seal_key: None,
    };
    can_events::install(
        can_events::EventStream::open(&config, can_events::StreamId::Proxy).expect("connect"),
    );
}

fn exchanges(events: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    events.iter().filter(|e| e["event"] == "exchange").collect()
}

fn decode_body(value: &serde_json::Value) -> String {
    let encoded = value["body_b64"].as_str().expect("body_b64");
    String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64"),
    )
    .expect("utf8")
}

#[tokio::test(flavor = "multi_thread")]
async fn capture_records_exchanges_without_ever_leaking_a_real_secret() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);

    let capture = can_events::CaptureConfig {
        exchanges: true,
        max_bytes: 64 * 1024,
    };
    install_stream(&socket_path, capture.clone());

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(capture).await;
    let client = client(proxy_addr);

    // The sandbox carries the fake credential in a custom header and in
    // the body; the proxy swaps in the real one before forwarding, and
    // the echo upstream sends it straight back.
    let response = client
        .post(format!("http://127.0.0.1:{}/echo", upstream.port()))
        .header("x-token", FAKE_SECRET)
        .header("authorization", format!("Bearer {FAKE_SECRET}"))
        .body(format!("{{\"token\":\"{FAKE_SECRET}\"}}"))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let echoed = response.text().await.expect("body");
    assert!(
        echoed.contains(REAL_SECRET),
        "the swap must really have happened, otherwise this test proves nothing"
    );

    let (events, raw) = reader.finish();

    assert!(
        !raw.contains(REAL_SECRET),
        "a real secret must never appear anywhere in the event stream"
    );
    assert!(
        !raw.contains(FAKE_SECRET),
        "the fake credential is redacted too, so captures carry no credential-shaped strings"
    );

    let captured = exchanges(&events);
    assert_eq!(captured.len(), 1, "one exchange for one request");
    let exchange = captured[0];

    assert_eq!(exchange["data"]["host"], "127.0.0.1");
    assert_eq!(exchange["data"]["request"]["method"], "POST");
    assert!(
        exchange["data"]["request"]["url"]
            .as_str()
            .expect("url")
            .ends_with("/echo")
    );

    let request_headers = exchange["data"]["request"]["headers"]
        .as_array()
        .expect("headers");
    let header = |name: &str| {
        request_headers
            .iter()
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].as_str().expect("value").to_string())
    };
    assert_eq!(header("authorization").as_deref(), Some("[redacted]"));
    assert_eq!(header("x-token").as_deref(), Some("[redacted]"));

    let request_body = decode_body(&exchange["data"]["request"]);
    assert_eq!(request_body, "{\"token\":\"[redacted]\"}");

    let response_body = decode_body(&exchange["data"]["response"]);
    assert!(
        response_body.contains("[redacted]"),
        "the echoed secret is scrubbed on the response side too: {response_body}"
    );

    assert_eq!(exchange["data"]["response"]["status"], 200);
    let timings = &exchange["data"]["timings"];
    assert!(timings["started_ms"].as_u64().expect("started") > 0);
    assert!(
        timings["ended_ms"].as_u64().expect("ended")
            >= timings["started_ms"].as_u64().expect("started")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn streamed_responses_keep_their_chunk_boundaries() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);

    let capture = can_events::CaptureConfig {
        exchanges: true,
        max_bytes: 64 * 1024,
    };
    install_stream(&socket_path, capture.clone());

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(capture).await;
    let client = client(proxy_addr);

    let response = client
        .post(format!("http://127.0.0.1:{}/stream", upstream.port()))
        .body("{}")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.text().await.expect("body");

    let (events, _raw) = reader.finish();
    let captured = exchanges(&events);
    assert_eq!(captured.len(), 1);

    let chunks = captured[0]["data"]["response"]["chunks"]
        .as_array()
        .expect("chunks");
    assert!(
        chunks.len() >= 2,
        "SSE frames must survive as separate chunks, got {}",
        chunks.len()
    );

    let mut rebuilt = String::new();
    let mut last_offset = 0;
    for chunk in chunks {
        let offset = chunk["offset_ms"].as_u64().expect("offset_ms");
        assert!(offset >= last_offset, "chunk offsets must not go backwards");
        last_offset = offset;
        rebuilt.push_str(
            &String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(chunk["data_b64"].as_str().expect("data_b64"))
                    .expect("base64"),
            )
            .expect("utf8"),
        );
    }

    assert_eq!(rebuilt, decode_body(&captured[0]["data"]["response"]));
    assert!(rebuilt.contains("data: [DONE]"));
    assert!(
        captured[0]["data"]["timings"]["first_byte_ms"]
            .as_u64()
            .is_some(),
        "a streamed response reports time to first byte"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bodies_over_the_cap_are_truncated_and_flagged() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);

    let capture = can_events::CaptureConfig {
        exchanges: true,
        max_bytes: 16,
    };
    install_stream(&socket_path, capture.clone());

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(capture).await;
    let client = client(proxy_addr);

    let payload = "x".repeat(200);
    let response = client
        .post(format!("http://127.0.0.1:{}/echo", upstream.port()))
        .body(payload.clone())
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.text().await.expect("body");

    let (events, _raw) = reader.finish();
    let captured = exchanges(&events);
    assert_eq!(captured.len(), 1);

    let request = &captured[0]["data"]["request"];
    assert_eq!(request["truncated"], true);
    assert_eq!(request["body_bytes"], payload.len() as u64);
    assert_eq!(decode_body(request).len(), 16);
}

#[tokio::test(flavor = "multi_thread")]
async fn capture_is_off_unless_asked_for() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);

    let capture = can_events::CaptureConfig::default();
    install_stream(&socket_path, capture.clone());

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(capture).await;
    let client = client(proxy_addr);

    let response = client
        .post(format!("http://127.0.0.1:{}/echo", upstream.port()))
        .body("hello")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.text().await.expect("body");

    let (events, _raw) = reader.finish();
    assert!(
        exchanges(&events).is_empty(),
        "no exchange events without --capture-exchanges"
    );
    assert!(
        events.iter().any(|e| e["event"] == "egress_request"),
        "the run is still observed, just without payloads"
    );
}
