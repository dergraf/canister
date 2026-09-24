//! End-to-end test for the structured event stream (ADR-0010): drive real
//! requests through the proxy with a stream installed, and read the JSON
//! lines off a Unix socket the way an orchestrator would.

use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;

use can_policy::config::{EgressMode, HostBlock, NetworkConfig};
use can_proxy::ca::DynamicCa;
use can_proxy::server::{ProxyServer, ProxyServerConfig};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reqwest::{Client, Proxy};
use tokio::net::TcpListener;

/// The installed event stream is process-global, so two tests in this
/// binary cannot own one at the same time. Taking this lock is what
/// makes each test's `install`/`uninstall` pair exclusive.
static EVENT_STREAM: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Collects the lines `can` writes, in order.
struct SocketReader {
    handle: std::thread::JoinHandle<Vec<String>>,
}

impl SocketReader {
    fn listen(path: &std::path::Path) -> Self {
        let listener = std::os::unix::net::UnixListener::bind(path).expect("bind event socket");
        let handle = std::thread::spawn(move || {
            let (conn, _addr) = listener.accept().expect("accept event connection");
            std::io::BufReader::new(conn)
                .lines()
                .map_while(Result::ok)
                .collect()
        });
        Self { handle }
    }

    /// Close the writing side first, then drain.
    fn finish(self) -> Vec<serde_json::Value> {
        can_events::uninstall();
        self.handle
            .join()
            .expect("reader thread")
            .iter()
            .map(|line| serde_json::from_str(line).expect("event line must be JSON"))
            .collect()
    }
}

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
                    let bytes = req.into_body().collect().await.expect("body").to_bytes();
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain")
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

/// An upstream that answers 200 while claiming, in the proxy's own
/// internal headers, that the proxy refused the request.
async fn start_lying_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<hyper::body::Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain")
                            .header("x-canister-error", "dlp-blocked")
                            .header("x-canister-dlp-detector", "canary_token")
                            .body(
                                Full::new(bytes::Bytes::from_static(b"exfiltrated"))
                                    .map_err(|never| match never {})
                                    .boxed(),
                            )
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

async fn start_proxy(canaries: Vec<String>, hosts: Vec<HostBlock>) -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().expect("ca"));
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_ips: vec!["127.0.0.1".to_string()],
        ..Default::default()
    };
    let config = ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts)
        .with_canaries(canaries);
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

fn events_of<'a>(events: &'a [serde_json::Value], name: &str) -> Vec<&'a serde_json::Value> {
    events.iter().filter(|e| e["event"] == name).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_streams_events_over_a_unix_socket() {
    let _exclusive = EVENT_STREAM.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);

    let config = can_events::EventConfig {
        target: can_events::EventTarget::Socket(socket_path.clone()),
        run_id: "r-proxy-test".to_string(),
        capture: can_events::CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: None,
    };
    can_events::install(
        can_events::EventStream::open(&config, can_events::StreamId::Proxy).expect("connect"),
    );

    let upstream = start_upstream().await;
    let canary = "CNRY-TEST-7Q2X".to_string();
    let hosts = vec![
        // The upstream is reached by IP literal; give it a contract so the
        // request shape is accepted, and a GET-only host to refuse a POST.
        HostBlock {
            domain: "127.0.0.1".to_string(),
            ..Default::default()
        },
        HostBlock {
            domain: "read-only.example".to_string(),
            methods: vec!["GET".to_string()],
            ..Default::default()
        },
    ];
    let proxy_addr = start_proxy(vec![canary.clone()], hosts).await;
    let client = client(proxy_addr);

    // 1. Allowed: plain request to the permitted IP literal.
    let allowed = client
        .post(format!("http://127.0.0.1:{}/echo", upstream.port()))
        .body("hello")
        .send()
        .await
        .expect("allowed request");
    assert_eq!(allowed.status(), StatusCode::OK);

    // 2. Blocked by the connect gate: a domain with no [[host]] block.
    let blocked = client
        .post("http://not-allowed.example/collect")
        .body("data")
        .send()
        .await
        .expect("blocked request");
    assert_eq!(blocked.status(), StatusCode::BAD_GATEWAY);

    // 3. Blocked by the contract gate: POST to a GET-only host.
    let refused = client
        .post("http://read-only.example/write")
        .body("data")
        .send()
        .await
        .expect("contract request");
    assert_eq!(refused.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // 4. Canary exfiltration attempt.
    let canary_attempt = client
        .post(format!("http://127.0.0.1:{}/echo", upstream.port()))
        .body(format!("leaking {canary}"))
        .send()
        .await
        .expect("canary request");
    assert_eq!(canary_attempt.status(), 451);

    let events = reader.finish();
    assert!(!events.is_empty(), "expected events on the socket");

    // Envelope invariants: schema, run id, stream, contiguous seq, and a
    // hash chain that links every line to its predecessor.
    let mut expected_prev = "0".repeat(64);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event["schema"], 1);
        assert_eq!(event["run_id"], "r-proxy-test");
        assert_eq!(event["stream"], "proxy");
        assert_eq!(event["seq"], i as u64);
        assert_eq!(event["prev_hash"], expected_prev);
        expected_prev = event["chain_hash"]
            .as_str()
            .expect("chain_hash")
            .to_string();
    }

    let egress = events_of(&events, "egress_request");
    let allowed_event = egress
        .iter()
        .find(|e| e["data"]["host"] == "127.0.0.1" && e["data"]["decision"] == "allowed")
        .expect("allowed egress event");
    assert_eq!(allowed_event["data"]["method"], "POST");
    assert_eq!(allowed_event["data"]["path"], "/echo");

    let policy_blocked = egress
        .iter()
        .find(|e| e["data"]["host"] == "not-allowed.example")
        .expect("policy-blocked egress event");
    assert_eq!(policy_blocked["data"]["decision"], "blocked");
    assert_eq!(policy_blocked["data"]["reason"], "policy");

    let contract_blocked = egress
        .iter()
        .find(|e| e["data"]["host"] == "read-only.example")
        .expect("contract-blocked egress event");
    assert_eq!(contract_blocked["data"]["decision"], "blocked");
    assert_eq!(contract_blocked["data"]["reason"], "contract");

    let violations = events_of(&events, "contract_violation");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0]["data"]["reason"], "method-not-allowed");
    assert_eq!(violations[0]["data"]["path"], "/write");

    let canary_fires = events_of(&events, "canary_fire");
    assert_eq!(canary_fires.len(), 1, "one canary fire expected");
    assert_eq!(canary_fires[0]["data"]["detector"], "canary_token");
    assert!(
        !canary_fires[0]["data"]["matched_redacted"]
            .as_str()
            .expect("redacted match")
            .contains("7Q2X"),
        "the raw canary value must never reach the stream"
    );

    let dlp_blocks = events_of(&events, "dlp_block");
    assert!(
        dlp_blocks
            .iter()
            .any(|e| e["data"]["detector"] == "canary_token"),
        "canary hit must also produce a dlp_block event"
    );
}

/// The destination must not get to write the proxy's verdict.
///
/// `egress_request` classifies a request by reading `x-canister-error`
/// off the response. Those headers are the proxy's own signalling, but
/// they arrive over the network on the allowed path, so an upstream that
/// sets them could make a successful exfiltration appear in the evidence
/// — and in the stats histogram — as a DLP block.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_cannot_forge_the_proxys_verdict() {
    let _exclusive = EVENT_STREAM.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);

    let config = can_events::EventConfig {
        target: can_events::EventTarget::Socket(socket_path.clone()),
        run_id: "r-forged-verdict".to_string(),
        capture: can_events::CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: None,
    };
    can_events::install(
        can_events::EventStream::open(&config, can_events::StreamId::Proxy).expect("connect"),
    );

    let upstream = start_lying_upstream().await;
    let hosts = vec![HostBlock {
        domain: "127.0.0.1".to_string(),
        ..Default::default()
    }];
    let proxy_addr = start_proxy(vec![], hosts).await;

    let response = client(proxy_addr)
        .get(format!("http://127.0.0.1:{}/exfil", upstream.port()))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.expect("body"), "exfiltrated");

    let events = reader.finish();
    let egress = events_of(&events, "egress_request");
    let forged = egress
        .iter()
        .find(|e| e["data"]["path"] == "/exfil")
        .expect("the request must be recorded");

    assert_eq!(
        forged["data"]["decision"], "allowed",
        "the request was allowed and the body was delivered; recording it as blocked \
         would let a destination decide what the evidence says about it"
    );
    assert!(
        forged["data"]["reason"].is_null(),
        "reason came from the upstream, not from the proxy: {forged}"
    );
}
