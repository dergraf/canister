//! A credential-scoped host takes only the swapped credential (ADR-0030),
//! through a real proxy.

use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use can_policy::config::{DlpConfig, EgressMode, HostBlock, NetworkConfig};
use can_proxy::ca::DynamicCa;
use can_proxy::server::{ProxyServer, ProxyServerConfig, SecretSwap};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reqwest::{Client, Proxy};
use tokio::net::TcpListener;

/// The event stream is process-global; tests here must not overlap.
static STREAM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const FAKE: &str = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const REAL: &str = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const FOREIGN: &str = "ghp_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

/// Answers with the `authorization` header it received, and counts requests.
async fn start_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let auth = req
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    async move {
                        Ok::<_, hyper::Error>(Response::new(
                            Full::new(hyper::body::Bytes::from(auth))
                                .map_err(|never| match never {})
                                .boxed(),
                        ))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    (addr, hits)
}

async fn start_proxy(bind_credentials: bool) -> SocketAddr {
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_ips: vec!["127.0.0.1".to_string()],
        dlp: Some(DlpConfig {
            enabled: Some(true),
            bind_credentials: Some(bind_credentials),
            ..Default::default()
        }),
        ..Default::default()
    };
    let hosts = vec![HostBlock {
        domain: "127.0.0.1".to_string(),
        allow_credentials: vec!["github_pat".to_string()],
        ..Default::default()
    }];
    let config = ProxyServerConfig::new(Arc::new(DynamicCa::generate().expect("ca")))
        .with_network(network)
        .with_hosts(hosts)
        .with_secret_swaps(vec![SecretSwap {
            fake: FAKE.to_string(),
            real: REAL.to_string(),
            detector: "github_pat".to_string(),
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

/// Collects the proxy's events from a Unix socket until uninstalled.
struct Events(std::thread::JoinHandle<Vec<String>>);

impl Events {
    fn install(dir: &std::path::Path) -> Self {
        let path = dir.join("events.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let handle = std::thread::spawn(move || {
            let (conn, _) = listener.accept().expect("accept");
            std::io::BufReader::new(conn)
                .lines()
                .map_while(Result::ok)
                .collect()
        });
        let config = can_events::EventConfig {
            target: can_events::EventTarget::Socket(path),
            run_id: "r-credentials".to_string(),
            capture: can_events::CaptureConfig::default(),
            stats_interval_ms: None,
            seal_key: None,
        };
        can_events::install(
            can_events::EventStream::open(&config, can_events::StreamId::Proxy).expect("open"),
        );
        Self(handle)
    }

    fn egress(self) -> Vec<serde_json::Value> {
        can_events::uninstall();
        self.0
            .join()
            .expect("reader")
            .iter()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("json"))
            .filter(|e| e["event"] == "egress_request")
            .map(|e| e["data"].clone())
            .collect()
    }
}

async fn get(proxy: SocketAddr, upstream: SocketAddr, auth: Option<&str>) -> reqwest::Response {
    let client = Client::builder()
        .proxy(Proxy::all(format!("http://{proxy}")).expect("proxy url"))
        .build()
        .expect("client");
    let mut request = client.get(format!("http://{upstream}/v1/messages"));
    if let Some(auth) = auth {
        request = request.header("authorization", format!("Bearer {auth}"));
    }
    request.send().await.expect("response")
}

#[tokio::test(flavor = "multi_thread")]
async fn each_request_to_a_scoped_host_says_which_credential_it_carried() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let events = Events::install(dir.path());
    let (upstream, _hits) = start_upstream().await;
    let proxy = start_proxy(false).await;

    let swapped = get(proxy, upstream, Some(FAKE)).await;
    assert_eq!(
        swapped.text().await.expect("body"),
        format!("Bearer {REAL}")
    );
    let foreign = get(proxy, upstream, Some(FOREIGN)).await;
    assert_eq!(
        foreign.text().await.expect("body"),
        format!("Bearer {FOREIGN}"),
        "without bind_credentials a foreign credential is forwarded, and recorded"
    );
    get(proxy, upstream, None).await;

    let credentials: Vec<_> = events
        .egress()
        .iter()
        .map(|e| e["credential"].clone())
        .collect();
    assert_eq!(credentials, vec!["swapped", "foreign", "none"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn with_bind_credentials_a_foreign_credential_is_refused_and_never_forwarded() {
    let _guard = STREAM_LOCK.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let events = Events::install(dir.path());
    let (upstream, hits) = start_upstream().await;
    let proxy = start_proxy(true).await;

    let foreign = get(proxy, upstream, Some(FOREIGN)).await;
    assert_eq!(foreign.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        foreign.headers()["x-canister-error"]
            .to_str()
            .expect("header"),
        "foreign-credential"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the foreign request never left"
    );

    let swapped = get(proxy, upstream, Some(FAKE)).await;
    assert_eq!(
        swapped.status(),
        StatusCode::OK,
        "the swapped credential still goes"
    );
    let none = get(proxy, upstream, None).await;
    assert_eq!(
        none.status(),
        StatusCode::OK,
        "an unauthenticated request still goes"
    );

    let egress = events.egress();
    assert_eq!(egress[0]["decision"], "blocked");
    assert_eq!(egress[0]["reason"], "foreign_credential");
    assert_eq!(egress[0]["credential"], "foreign");
    assert_eq!(egress[1]["credential"], "swapped");
    assert_eq!(egress[2]["credential"], "none");
}
