//! Periodic `stats` events (ADR-0015): cumulative counters and a
//! fixed-bucket latency histogram, emitted on the configured interval.

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

static STREAM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
                let service = service_fn(|_req: Request<hyper::body::Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(
                                Full::new(bytes::Bytes::from_static(b"ok"))
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

async fn start_proxy(interval_ms: Option<u64>) -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().expect("ca"));
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_ips: vec!["127.0.0.1".to_string()],
        ..Default::default()
    };
    let hosts = vec![HostBlock {
        domain: "127.0.0.1".to_string(),
        methods: vec!["GET".to_string()],
        ..Default::default()
    }];
    let config = ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts)
        .with_stats_interval_ms(interval_ms);
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

fn install_stream(path: &std::path::Path, interval_ms: Option<u64>) {
    let config = can_events::EventConfig {
        target: can_events::EventTarget::Socket(path.to_path_buf()),
        run_id: "r-stats".to_string(),
        capture: can_events::CaptureConfig::default(),
        stats_interval_ms: interval_ms,
        seal_key: None,
    };
    can_events::install(
        can_events::EventStream::open(&config, can_events::StreamId::Proxy).expect("connect"),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_report_requests_violations_and_latency() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);
    install_stream(&socket_path, Some(150));

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(Some(150)).await;
    let client = client(proxy_addr);

    // Two allowed GETs and one POST refused by the GET-only contract.
    for _ in 0..2 {
        let response = client
            .get(format!("http://127.0.0.1:{}/ping", upstream.port()))
            .send()
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
    }
    let refused = client
        .post(format!("http://127.0.0.1:{}/ping", upstream.port()))
        .body("{}")
        .send()
        .await
        .expect("request");
    assert_eq!(refused.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // Long enough for at least one tick after the requests.
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let events = reader.finish();
    let stats: Vec<&serde_json::Value> = events.iter().filter(|e| e["event"] == "stats").collect();
    assert!(!stats.is_empty(), "the ticker must emit snapshots");

    // The collector is process-global and other tests in this binary
    // share it, so assert on relationships rather than absolutes.
    let latest = stats.last().expect("a snapshot");
    let data = &latest["data"];
    let allowed = data["requests_by_decision"]["allowed"]
        .as_u64()
        .expect("allowed");
    let blocked = data["requests_by_decision"]["blocked"]
        .as_u64()
        .expect("blocked");
    assert!(allowed >= 2, "two allowed GETs: {allowed}");
    assert!(blocked >= 1, "one refused POST: {blocked}");
    assert!(
        data["contract_violations_by_reason"]["method-not-allowed"]
            .as_u64()
            .expect("violations")
            >= 1
    );

    let histogram = &data["proxy_latency_ms"];
    assert_eq!(
        histogram["count"].as_u64().expect("count"),
        allowed + blocked,
        "every proxied request is observed exactly once"
    );
    let buckets = histogram["buckets_ms"].as_array().expect("buckets");
    let counts = histogram["counts"].as_array().expect("counts");
    assert_eq!(
        counts.len(),
        buckets.len() + 1,
        "one count per bucket plus +Inf"
    );
    assert_eq!(
        counts
            .iter()
            .map(|c| c.as_u64().expect("count"))
            .sum::<u64>(),
        allowed + blocked
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshots_are_cumulative() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);
    install_stream(&socket_path, Some(150));

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(Some(150)).await;
    let client = client(proxy_addr);

    client
        .get(format!("http://127.0.0.1:{}/one", upstream.port()))
        .send()
        .await
        .expect("request");
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    client
        .get(format!("http://127.0.0.1:{}/two", upstream.port()))
        .send()
        .await
        .expect("request");
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    let events = reader.finish();
    let counts: Vec<u64> = events
        .iter()
        .filter(|e| e["event"] == "stats")
        .filter_map(|e| e["data"]["requests_by_decision"]["allowed"].as_u64())
        .collect();

    assert!(counts.len() >= 2, "expected several snapshots: {counts:?}");
    assert!(
        counts.windows(2).all(|w| w[1] >= w[0]),
        "counters never go backwards: {counts:?}"
    );
    assert!(
        counts.last().expect("last") - counts.first().expect("first") >= 1,
        "the second request shows up in a later snapshot: {counts:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_interval_means_no_periodic_stats() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);
    install_stream(&socket_path, None);

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(None).await;

    client(proxy_addr)
        .get(format!("http://127.0.0.1:{}/ping", upstream.port()))
        .send()
        .await
        .expect("request");
    tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;

    let events = reader.finish();
    assert!(
        !events.iter().any(|e| e["event"] == "stats"),
        "stats are opt-in"
    );
    let _ = &events;
    assert!(
        events.iter().any(|e| e["event"] == "egress_request"),
        "the request itself is still observed"
    );
}
