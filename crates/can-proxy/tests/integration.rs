use base64::Engine;
use bytes::Bytes;
use can_policy::config::{EgressMode, NetworkConfig};
use can_proxy::ca::DynamicCa;
use can_proxy::server::ProxyServer;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reqwest::{Client, Proxy};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
async fn start_test_proxy() -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().unwrap());
    let config = can_proxy::server::ProxyServerConfig::new(ca);
    let proxy = ProxyServer::new(config).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let proxy = Arc::new(proxy);
    tokio::spawn(async move {
        proxy.run(listener).await.unwrap();
    });

    addr
}

async fn start_test_proxy_with_network(network: NetworkConfig) -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().unwrap());
    let config = can_proxy::server::ProxyServerConfig::new(ca).with_network(network);
    let proxy = ProxyServer::new(config).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        proxy.run(listener).await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    addr
}

async fn start_test_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    if req.uri().path() == "/echo" {
                        let bytes = req.into_body().collect().await.unwrap().to_bytes();
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain")
                            .body(Full::new(bytes).map_err(|never| match never {}).boxed())
                            .unwrap();
                        return Ok::<_, hyper::Error>(resp);
                    }

                    let resp = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(
                            Full::new(bytes::Bytes::from_static(b"not found"))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .unwrap();
                    Ok::<_, hyper::Error>(resp)
                });

                if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                    panic!("upstream server error: {err}");
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn test_http_passthrough() {
    let addr = start_test_proxy().await;
    let proxy_url = format!("http://{}", addr);

    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let res = client
        .get("http://httpbin.org/get")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(body.contains("\"url\": \"http://httpbin.org/get\""));
}

#[tokio::test]
async fn test_https_passthrough() {
    let addr = start_test_proxy().await;
    let proxy_url = format!("http://{}", addr);

    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let res = client
        .get("https://httpbin.org/get")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(body.contains("\"url\": \"https://httpbin.org/get\""));
}

#[tokio::test]
async fn test_proxy_blocks_disallowed_domain_by_network_policy() {
    let upstream = start_test_upstream().await;
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_domains: vec!["localhost".to_string()],
        ..Default::default()
    };

    let addr = start_test_proxy_with_network(network).await;
    let proxy_url = format!("http://{}", addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let blocked = client.get("https://www.google.com").send().await;
    assert!(
        blocked.is_err()
            || blocked
                .as_ref()
                .map(|r| r.status().is_server_error() || r.status().is_client_error())
                .unwrap_or(false),
        "expected google.com to be blocked by proxy"
    );

    let allowed = client
        .get(format!("http://localhost:{}/echo", upstream.port()))
        .send()
        .await
        .expect("expected allowed domain to pass through proxy");
    assert_eq!(allowed.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_websocket_upgrade_returns_not_implemented_for_now() {
    let proxy_addr = start_test_proxy().await;

    let stream = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(true)
        .handshake(io)
        .await
        .unwrap();

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("http://example.com/ws")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-key", "x3JJHMbDL1EzLkh9GBhXDw==")
        .header("sec-websocket-version", "13")
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap();

    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_IMPLEMENTED);
}

// ============================================================================
// DLP integration tests
// ============================================================================

async fn start_dlp_proxy(
    allow_domains: Vec<String>,
    strict: bool,
    monitor: bool,
    canaries: Vec<String>,
) -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().unwrap());
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_domains,
        dlp: None,
        ..Default::default()
    };
    let config = can_proxy::server::ProxyServerConfig::new(ca)
        .with_network(network)
        .with_strict(strict)
        .with_monitor(monitor)
        .with_canaries(canaries);
    let proxy = ProxyServer::new(config).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        proxy.run(listener).await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    addr
}

fn make_proxy_client(proxy_addr: SocketAddr) -> Client {
    let proxy_url = format!("http://{}", proxy_addr);
    Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap()
}

#[tokio::test]
async fn dlp_allows_clean_request() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .post(&url)
        .body("just regular data")
        .send()
        .await
        .expect("clean request should succeed");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn dlp_blocks_github_pat_in_header_to_wrong_host() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("ghp_{}", "A".repeat(36));
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(&url)
        .header("Authorization", format!("token {token}"))
        .send()
        .await
        .expect("DLP should return a response, not a connection error");

    assert_eq!(res.status().as_u16(), 451);
    assert_eq!(
        res.headers()
            .get("x-canister-error")
            .and_then(|v| v.to_str().ok()),
        Some("dlp-blocked"),
    );
    assert_eq!(
        res.headers()
            .get("x-canister-dlp-detector")
            .and_then(|v| v.to_str().ok()),
        Some("GithubPat"),
    );
}

#[tokio::test]
async fn dlp_warns_github_pat_to_home_domain() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("ghp_{}", "A".repeat(36));
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(&url)
        .header("Authorization", format!("token {token}"))
        .send()
        .await
        .expect("DLP should return a response");

    assert_eq!(res.status().as_u16(), 451);
}

#[tokio::test]
async fn dlp_blocks_ssh_private_key_in_header() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(&url)
        .header("X-Custom", "-----BEGIN RSA PRIVATE KEY-----")
        .send()
        .await
        .expect("DLP should return a response");

    assert_eq!(res.status().as_u16(), 451);
    assert_eq!(
        res.headers()
            .get("x-canister-dlp-detector")
            .and_then(|v| v.to_str().ok()),
        Some("SshPrivateKey"),
    );
}

#[tokio::test]
async fn dlp_blocks_token_in_request_body() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("ghp_{}", "B".repeat(36));
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .post(&url)
        .body(format!("data with secret {token} inside"))
        .send()
        .await
        .expect("DLP should return a response");

    assert_eq!(res.status().as_u16(), 451);
}

#[tokio::test]
async fn dlp_blocks_base64_encoded_token_in_body() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("ghp_{}", "C".repeat(36));
    let encoded = base64::engine::general_purpose::STANDARD.encode(&token);
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .post(&url)
        .body(encoded)
        .send()
        .await
        .expect("DLP should return a response");

    assert_eq!(res.status().as_u16(), 451);
}

#[tokio::test]
async fn dlp_blocks_token_in_uri_query() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("npm_{}", "D".repeat(36));
    let url = format!("http://127.0.0.1:{}/echo?secret={token}", upstream.port());
    let res = client
        .get(&url)
        .send()
        .await
        .expect("DLP should return a response");

    assert_eq!(res.status().as_u16(), 451);
}

#[tokio::test]
async fn dlp_monitor_mode_allows_blocked_request() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, true, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("ghp_{}", "E".repeat(36));
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(&url)
        .header("Authorization", format!("token {token}"))
        .send()
        .await
        .expect("monitor mode should allow the request through");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn dlp_canary_token_always_blocked() {
    let upstream = start_test_upstream().await;
    let canary = format!("ghp_{}", "Z".repeat(36));
    let proxy_addr = start_dlp_proxy(
        vec!["127.0.0.1".to_string()],
        false,
        false,
        vec![canary.clone()],
    )
    .await;
    let client = make_proxy_client(proxy_addr);

    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(&url)
        .header("X-Token", &canary)
        .send()
        .await
        .expect("DLP should return a response");

    assert_eq!(res.status().as_u16(), 451);
    assert_eq!(
        res.headers()
            .get("x-canister-dlp-detector")
            .and_then(|v| v.to_str().ok()),
        Some("CanaryToken"),
    );
}

#[tokio::test]
async fn dlp_bearer_token_allowed_to_allowed_domain() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("Bearer {}", "F".repeat(40));
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(&url)
        .header("Authorization", &token)
        .send()
        .await
        .expect("bearer token to allowed domain should pass");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn dlp_strict_promotes_warn_to_block() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], true, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("Bearer {}", "G".repeat(40));
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(&url)
        .header("Authorization", &token)
        .send()
        .await
        .expect("bearer to allowed domain in strict should still pass");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn dlp_blocks_gzip_encoded_token_in_body() {
    use std::io::Write;

    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("ghp_{}", "H".repeat(36));
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(token.as_bytes()).unwrap();
    let compressed = encoder.finish().unwrap();

    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .post(&url)
        .header("content-encoding", "gzip")
        .body(compressed)
        .send()
        .await
        .expect("DLP should return a response");

    assert_eq!(res.status().as_u16(), 451);
}

#[tokio::test]
async fn dlp_non_sensitive_headers_not_scanned() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("ghp_{}", "I".repeat(36));
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(&url)
        .header("Accept", &token)
        .send()
        .await
        .expect("non-sensitive header should not trigger DLP");

    assert_eq!(res.status(), StatusCode::OK);
}
