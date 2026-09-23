//! External, tagged canaries (ADR-0012) through a real proxy: an allowed
//! destination observes the flow, any other destination is a leak, and
//! monitor mode records without blocking.

use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;

use can_policy::config::{EgressMode, ExternalCanary, HostBlock, NetworkConfig};
use can_proxy::ca::DynamicCa;
use can_proxy::server::{ProxyServer, ProxyServerConfig};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reqwest::{Client, Proxy};
use tokio::net::TcpListener;

/// The event stream is process-global; these tests must not overlap.
static STREAM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const AHV_CANARY: &str = "CNRY-7Q2X-AHV";

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
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let bytes = req.into_body().collect().await.expect("body").to_bytes();
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

/// The upstream listens on 127.0.0.1, so "which destination" is encoded
/// in the `Host` header: both `claims.mock.internal` and
/// `medcodes.mock.internal` resolve to the same loopback listener through
/// the proxy's IP allow-list.
async fn start_proxy(monitor: bool, allowed_hosts: &[&str]) -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().expect("ca"));
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_ips: vec!["127.0.0.1".to_string()],
        ..Default::default()
    };
    let hosts = vec![HostBlock {
        domain: "127.0.0.1".to_string(),
        ..Default::default()
    }];
    let config = ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts)
        .with_monitor(monitor)
        .with_external_canaries(vec![ExternalCanary {
            value: AHV_CANARY.to_string(),
            data_class: "ahv".to_string(),
            allowed_hosts: allowed_hosts.iter().map(|h| h.to_string()).collect(),
        }]);
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

fn install_stream(path: &std::path::Path) {
    let config = can_events::EventConfig {
        target: can_events::EventTarget::Socket(path.to_path_buf()),
        run_id: "r-canaries".to_string(),
        capture: can_events::CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: None,
    };
    can_events::install(
        can_events::EventStream::open(&config, can_events::StreamId::Proxy).expect("connect"),
    );
}

fn events_of<'a>(events: &'a [serde_json::Value], name: &str) -> Vec<&'a serde_json::Value> {
    events.iter().filter(|e| e["event"] == name).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_destination_records_the_flow_without_blocking() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);
    install_stream(&socket_path);

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(false, &["127.0.0.1"]).await;

    let response = client(proxy_addr)
        .post(format!("http://127.0.0.1:{}/claims", upstream.port()))
        .body(format!("{{\"ahv\":\"{AHV_CANARY}\"}}"))
        .send()
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an allowed data class must not be blocked"
    );

    // The value is seen more than once (request body, and again in the
    // echoed response); every sighting must be classified the same way.
    let events = reader.finish();
    let fires = events_of(&events, "canary_fire");
    assert!(!fires.is_empty(), "the flow must be recorded");
    for fire in &fires {
        assert_eq!(fire["data"]["data_class"], "ahv");
        assert_eq!(fire["data"]["allowed"], true);
    }
    assert!(
        fires.iter().any(|f| f["data"]["location"] == "body"),
        "the request-body sighting is reported with its location"
    );
    assert!(
        events_of(&events, "dlp_block").is_empty(),
        "an expected flow is not a DLP block"
    );

    let egress = events_of(&events, "egress_request");
    assert_eq!(egress[0]["data"]["decision"], "allowed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_destination_outside_the_allow_list_is_blocked() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);
    install_stream(&socket_path);

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(false, &["claims.mock.internal"]).await;

    let response = client(proxy_addr)
        .post(format!("http://127.0.0.1:{}/lookup", upstream.port()))
        .body(format!("{{\"ahv\":\"{AHV_CANARY}\"}}"))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), 451, "a leak is refused");

    let events = reader.finish();
    let fires = events_of(&events, "canary_fire");
    assert_eq!(fires.len(), 1);
    assert_eq!(fires[0]["data"]["data_class"], "ahv");
    assert_eq!(fires[0]["data"]["allowed"], false);

    let blocks = events_of(&events, "dlp_block");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0]["data"]["blocked"], true);

    let egress = events_of(&events, "egress_request");
    assert_eq!(egress[0]["data"]["decision"], "blocked");
    assert_eq!(egress[0]["data"]["reason"], "canary_token");
}

#[tokio::test(flavor = "multi_thread")]
async fn monitor_mode_records_the_leak_without_blocking_it() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);
    install_stream(&socket_path);

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(true, &["claims.mock.internal"]).await;

    let response = client(proxy_addr)
        .post(format!("http://127.0.0.1:{}/lookup", upstream.port()))
        .body(format!("{{\"ahv\":\"{AHV_CANARY}\"}}"))
        .send()
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "monitor mode never blocks"
    );

    let events = reader.finish();
    let fires = events_of(&events, "canary_fire");
    assert!(!fires.is_empty());
    for fire in &fires {
        assert_eq!(fire["data"]["allowed"], false);
    }

    let blocks = events_of(&events, "dlp_block");
    assert!(!blocks.is_empty());
    for block in &blocks {
        assert_eq!(
            block["data"]["blocked"], false,
            "monitor mode reports findings as observed, not enforced"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_canary_in_a_header_is_reported_with_its_location() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let socket_path = dir.path().join("events.sock");
    let reader = SocketReader::listen(&socket_path);
    install_stream(&socket_path);

    let upstream = start_upstream().await;
    let proxy_addr = start_proxy(false, &[]).await;

    let response = client(proxy_addr)
        .post(format!("http://127.0.0.1:{}/lookup", upstream.port()))
        .header("x-patient", AHV_CANARY)
        .body("{}")
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), 451);

    let events = reader.finish();
    let fires = events_of(&events, "canary_fire");
    assert_eq!(fires.len(), 1);
    assert_eq!(fires[0]["data"]["location"], "header");
    assert_eq!(fires[0]["data"]["allowed"], false);
    assert!(
        !fires[0]["data"]["matched_redacted"]
            .as_str()
            .expect("redacted")
            .contains("7Q2X"),
        "the canary value itself is redacted"
    );
}
