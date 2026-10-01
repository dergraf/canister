//! The undeclared-host sink (ADR-0018), end to end through a real proxy.
//!
//! The upstream these tests run is reachable as `localhost`, and counts
//! every connection it accepts. A request the sink answers must leave
//! that count at zero: the sink scans and answers locally, and never
//! dials. The control test proves the counter would see a forward.

use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use can_policy::config::{EgressMode, HostBlock, NetworkConfig, UndeclaredHosts};
use can_proxy::ca::DynamicCa;
use can_proxy::server::{ProxyServer, ProxyServerConfig};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reqwest::{Client, Proxy};
use tokio::net::TcpListener;

const SINK_BODY: &str = "Forbidden: host not declared; request not forwarded";
const CANARY: &str = "CNRY-SINK-4K9Z";

/// The installed event stream is process-global; one test owns it at a time.
static EVENT_STREAM: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct EventCapture {
    handle: std::thread::JoinHandle<Vec<String>>,
    _dir: tempfile::TempDir,
}

impl EventCapture {
    fn install(run_id: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("events.sock");
        let listener =
            std::os::unix::net::UnixListener::bind(&socket_path).expect("bind event socket");
        let handle = std::thread::spawn(move || {
            let (conn, _addr) = listener.accept().expect("accept event connection");
            std::io::BufReader::new(conn)
                .lines()
                .map_while(Result::ok)
                .collect()
        });

        let config = can_events::EventConfig {
            target: can_events::EventTarget::Socket(socket_path),
            run_id: run_id.to_string(),
            capture: can_events::CaptureConfig::default(),
            stats_interval_ms: None,
            seal_key: None,
        };
        can_events::install(
            can_events::EventStream::open(&config, can_events::StreamId::Proxy).expect("connect"),
        );
        Self { handle, _dir: dir }
    }

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

fn events_of<'a>(events: &'a [serde_json::Value], name: &str) -> Vec<&'a serde_json::Value> {
    events.iter().filter(|e| e["event"] == name).collect()
}

/// An HTTP upstream on 127.0.0.1 that counts accepted connections.
async fn start_counting_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(|_req: Request<hyper::body::Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(
                                Full::new(bytes::Bytes::from_static(b"upstream"))
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

    (addr, accepted)
}

fn host(domain: &str) -> HostBlock {
    HostBlock {
        domain: domain.to_string(),
        ..Default::default()
    }
}

async fn start_proxy(
    egress: EgressMode,
    undeclared_hosts: Option<UndeclaredHosts>,
    hosts: Vec<HostBlock>,
) -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().expect("ca"));
    let network = NetworkConfig {
        egress: Some(egress),
        undeclared_hosts,
        allow_ips: vec!["127.0.0.1".to_string()],
        ..Default::default()
    };
    let config = ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts)
        .with_canaries(vec![CANARY.to_string()]);
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
        // The proxy terminates TLS with a CA generated for this run.
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_declared_host_is_forwarded_so_the_counter_would_see_a_leak() {
    let _exclusive = EVENT_STREAM.lock().await;
    let (upstream, accepted) = start_counting_upstream().await;
    let proxy = start_proxy(
        EgressMode::ProxyOnly,
        Some(UndeclaredHosts::Sink),
        vec![host("localhost")],
    )
    .await;

    let response = client(proxy)
        .get(format!("http://localhost:{}/ok", upstream.port()))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.expect("body"), "upstream");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn by_default_an_undeclared_host_is_refused_at_connect() {
    let _exclusive = EVENT_STREAM.lock().await;
    let events = EventCapture::install("r-sink-default");
    let (upstream, accepted) = start_counting_upstream().await;
    let proxy = start_proxy(EgressMode::ProxyOnly, None, vec![host("declared.example")]).await;

    let https = client(proxy)
        .post(format!("https://localhost:{}/upload", upstream.port()))
        .body("payload")
        .send()
        .await;
    assert!(
        https.is_err(),
        "the CONNECT is refused, so no TLS session exists: {https:?}"
    );

    let http = client(proxy)
        .post(format!("http://localhost:{}/upload", upstream.port()))
        .body("payload")
        .send()
        .await
        .expect("plain request");
    assert_eq!(http.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        http.headers()["x-canister-error"].to_str().expect("header"),
        "policy-blocked"
    );

    let events = events.finish();
    assert_eq!(accepted.load(Ordering::SeqCst), 0);

    let egress = events_of(&events, "egress_request");
    let connect = egress
        .iter()
        .find(|e| e["data"]["method"] == "CONNECT")
        .expect("CONNECT event");
    assert_eq!(connect["data"]["host"], "localhost");
    assert_eq!(connect["data"]["decision"], "blocked");
    assert_eq!(connect["data"]["reason"], "policy");
    assert!(
        egress.iter().all(|e| e["data"]["reason"] != "sink"),
        "nothing is sunk unless asked for: {egress:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sink_answers_an_undeclared_https_request_locally() {
    let _exclusive = EVENT_STREAM.lock().await;
    let events = EventCapture::install("r-sink-https");
    let (upstream, accepted) = start_counting_upstream().await;
    let proxy = start_proxy(
        EgressMode::ProxyOnly,
        Some(UndeclaredHosts::Sink),
        vec![host("declared.example")],
    )
    .await;

    let response = client(proxy)
        .post(format!("https://localhost:{}/upload?x=1", upstream.port()))
        .body("payload")
        .send()
        .await
        .expect("the sink completes the TLS handshake and answers");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()["x-canister-error"]
            .to_str()
            .expect("header"),
        "undeclared-host-sink"
    );
    assert_eq!(response.text().await.expect("body"), SINK_BODY);

    let events = events.finish();
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "the sink must never dial the destination"
    );

    let egress = events_of(&events, "egress_request");
    assert_eq!(egress.len(), 2, "one for the CONNECT, one for the request");
    let connect = egress
        .iter()
        .find(|e| e["data"]["method"] == "CONNECT")
        .expect("CONNECT event");
    assert_eq!(connect["data"]["host"], "localhost");
    assert_eq!(connect["data"]["decision"], "blocked");
    assert_eq!(connect["data"]["reason"], "sink");

    let request = egress
        .iter()
        .find(|e| e["data"]["method"] == "POST")
        .expect("request event");
    assert_eq!(request["data"]["host"], "localhost");
    assert_eq!(request["data"]["path"], "/upload");
    assert_eq!(request["data"]["decision"], "blocked");
    assert_eq!(request["data"]["reason"], "sink");

    assert!(events_of(&events, "canary_fire").is_empty());
    assert!(events_of(&events, "dlp_block").is_empty());
    assert!(
        events_of(&events, "contract_violation").is_empty(),
        "an undeclared host has no contract to violate"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sink_answers_an_undeclared_plain_http_request_locally() {
    let _exclusive = EVENT_STREAM.lock().await;
    let events = EventCapture::install("r-sink-http");
    let (upstream, accepted) = start_counting_upstream().await;
    let proxy = start_proxy(
        EgressMode::ProxyOnly,
        Some(UndeclaredHosts::Sink),
        vec![host("declared.example")],
    )
    .await;

    let response = client(proxy)
        .get(format!("http://localhost:{}/probe", upstream.port()))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.text().await.expect("body"), SINK_BODY);

    let events = events.finish();
    assert_eq!(accepted.load(Ordering::SeqCst), 0);

    let egress = events_of(&events, "egress_request");
    assert_eq!(egress.len(), 1, "plain HTTP has no CONNECT: {egress:?}");
    assert_eq!(egress[0]["data"]["method"], "GET");
    assert_eq!(egress[0]["data"]["path"], "/probe");
    assert_eq!(egress[0]["data"]["decision"], "blocked");
    assert_eq!(egress[0]["data"]["reason"], "sink");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_canary_sent_to_an_undeclared_host_fires() {
    let _exclusive = EVENT_STREAM.lock().await;
    let events = EventCapture::install("r-sink-canary");
    let (upstream, accepted) = start_counting_upstream().await;
    let proxy = start_proxy(
        EgressMode::ProxyOnly,
        Some(UndeclaredHosts::Sink),
        vec![host("declared.example")],
    )
    .await;

    let response = client(proxy)
        .post(format!("https://localhost:{}/collect", upstream.port()))
        .header("content-type", "application/json")
        .body(format!("{{\"note\":\"leaking {CANARY}\"}}"))
        .send()
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the answer does not reveal that a detector fired"
    );
    assert_eq!(response.text().await.expect("body"), SINK_BODY);

    let events = events.finish();
    assert_eq!(accepted.load(Ordering::SeqCst), 0);

    let fires = events_of(&events, "canary_fire");
    assert_eq!(fires.len(), 1, "{events:?}");
    assert_eq!(fires[0]["data"]["host"], "localhost");
    assert_eq!(fires[0]["data"]["detector"], "canary_token");
    assert_eq!(fires[0]["data"]["allowed"], false);
    assert!(
        !fires[0]["data"]["matched_redacted"]
            .as_str()
            .expect("redacted match")
            .contains("4K9Z"),
        "the raw canary value must never reach the stream"
    );

    let blocks = events_of(&events, "dlp_block");
    assert!(
        blocks
            .iter()
            .any(|e| e["data"]["detector"] == "canary_token" && e["data"]["host"] == "localhost"),
        "{blocks:?}"
    );

    let request = events_of(&events, "egress_request")
        .into_iter()
        .find(|e| e["data"]["method"] == "POST")
        .expect("request event");
    assert_eq!(request["data"]["decision"], "blocked");
    assert_eq!(request["data"]["reason"], "sink");
}

#[tokio::test(flavor = "multi_thread")]
async fn ip_literals_are_refused_even_in_sink_mode() {
    let _exclusive = EVENT_STREAM.lock().await;
    let proxy = start_proxy(
        EgressMode::ProxyOnly,
        Some(UndeclaredHosts::Sink),
        vec![host("declared.example")],
    )
    .await;

    let response = client(proxy)
        .get("http://198.51.100.7/probe")
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.headers()["x-canister-error"]
            .to_str()
            .expect("header"),
        "policy-blocked"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_dlp_the_sink_falls_back_to_refusing() {
    let _exclusive = EVENT_STREAM.lock().await;
    let (upstream, accepted) = start_counting_upstream().await;
    // `direct` egress turns the DLP pipeline off; the sink has nothing to
    // scan with, so the proxy refuses as it does by default.
    let proxy = start_proxy(
        EgressMode::Direct,
        Some(UndeclaredHosts::Sink),
        vec![host("declared.example")],
    )
    .await;

    let http = client(proxy)
        .get(format!("http://localhost:{}/probe", upstream.port()))
        .send()
        .await
        .expect("request");
    assert_ne!(http.status(), StatusCode::FORBIDDEN);
    assert_ne!(http.status(), StatusCode::OK);

    let https = client(proxy)
        .get(format!("https://localhost:{}/probe", upstream.port()))
        .send()
        .await;
    assert!(https.is_err(), "the CONNECT is refused: {https:?}");

    assert_eq!(accepted.load(Ordering::SeqCst), 0);
}
