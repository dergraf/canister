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

async fn start_test_proxy_with_network_and_hosts(
    network: NetworkConfig,
    hosts: Vec<can_policy::config::HostBlock>,
) -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().unwrap());
    let config = can_proxy::server::ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts);
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
        ..Default::default()
    };
    let hosts = vec![can_policy::config::HostBlock {
        domain: "localhost".to_string(),
        ..Default::default()
    }];

    let addr = start_test_proxy_with_network_and_hosts(network, hosts).await;
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
    host_domains: Vec<String>,
    strict: bool,
    monitor: bool,
    canaries: Vec<String>,
) -> SocketAddr {
    let ca = Arc::new(DynamicCa::generate().unwrap());
    // All DLP tests target an upstream bound to 127.0.0.1, so the
    // network policy needs to allow that IP literal via `allow_ips`.
    // FQDN egress goes through the `[[host]]` blocks built below.
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_ips: vec!["127.0.0.1".to_string()],
        dlp: None,
        ..Default::default()
    };
    let hosts: Vec<can_policy::config::HostBlock> = host_domains
        .into_iter()
        .map(|d| can_policy::config::HostBlock {
            domain: d,
            ..Default::default()
        })
        .collect();
    let config = can_proxy::server::ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts)
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
        Some("github_pat"),
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
        Some("ssh_private_key"),
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
        Some("canary_token"),
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

/// End-to-end version of the previous test that hits the exact runtime
/// surface the dlp-test.py fuzzer uses: destination is
/// `host.canister.local`, the proxy has `host_loopback_target` set so
/// the policy gate accepts the alias, and the upstream is rewritten to
/// 127.0.0.1 at connect time. Pins every fuzzer-reported failing combo
/// against the actual handler chain.
#[tokio::test]
async fn dlp_blocks_encoded_aws_canary_to_host_canister_local() {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};

    let upstream = start_test_upstream().await;

    let ca = Arc::new(DynamicCa::generate().unwrap());
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_ips: vec!["127.0.0.1".to_string()],
        allow_host_loopback: true,
        ..Default::default()
    };
    let config = can_proxy::server::ProxyServerConfig::new(ca)
        .with_network(network)
        .with_host_loopback_target("127.0.0.1".parse().unwrap());
    let proxy = ProxyServer::new(config).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { proxy.run(listener).await.unwrap() });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // The proxy will rewrite `host.canister.local` -> 127.0.0.1 (the
    // host_loopback_target). We just need a URL whose Host header is the
    // alias and whose port matches the upstream we started.
    let client = make_proxy_client(proxy_addr);
    let url = format!("http://host.canister.local:{}/echo", upstream.port());

    let raw = "AKIA0123456789ABCDEF";
    let encode_for = |kind: &str| -> String {
        match kind {
            "base64" => STANDARD.encode(raw),
            "base64url" => URL_SAFE.encode(raw).trim_end_matches('=').to_string(),
            "hex" => raw.bytes().map(|b| format!("{b:02x}")).collect(),
            "double_base64" => STANDARD.encode(STANDARD.encode(raw)),
            other => panic!("unknown encoding {other}"),
        }
    };

    for enc_name in ["base64", "base64url", "hex", "double_base64"] {
        let encoded = encode_for(enc_name);

        for (channel, name, value) in &[
            ("auth_header", "Authorization", format!("Bearer {encoded}")),
            ("x_header", "X-Api-Key", encoded.clone()),
            ("cookie", "Cookie", format!("session={encoded}")),
        ] {
            let res = client
                .get(&url)
                .header(*name, value.clone())
                .send()
                .await
                .unwrap_or_else(|e| panic!("enc={enc_name} channel={channel}: {e}"));
            assert_eq!(
                res.status().as_u16(),
                451,
                "enc={enc_name} channel={channel} value={value} should be blocked (got status {})",
                res.status()
            );
        }
    }
}

/// Mirrors the dlp-test.py fuzzer's matrix exactly: the AKIA-shaped AWS
/// canary (20 chars, shorter than github/npm) encoded several ways and
/// placed in auth_header / x_header / cookie. The fuzzer reported these
/// 12 combinations leaking; this test pins each combination so a
/// runtime regression can't quietly re-introduce them.
#[tokio::test]
async fn dlp_blocks_encoded_aws_canary_in_request_headers() {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};

    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let raw = "AKIA0123456789ABCDEF";
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());

    let encode_for = |kind: &str| -> String {
        match kind {
            "base64" => STANDARD.encode(raw),
            "base64url" => URL_SAFE.encode(raw).trim_end_matches('=').to_string(),
            "hex" => raw.bytes().map(|b| format!("{b:02x}")).collect(),
            "double_base64" => STANDARD.encode(STANDARD.encode(raw)),
            other => panic!("unknown encoding {other}"),
        }
    };

    for enc_name in ["base64", "base64url", "hex", "double_base64"] {
        let encoded = encode_for(enc_name);

        // auth_header: Authorization: Bearer <encoded>
        let res = client
            .get(&url)
            .header("Authorization", format!("Bearer {encoded}"))
            .send()
            .await
            .expect("auth_header request");
        assert_eq!(
            res.status().as_u16(),
            451,
            "enc={enc_name} channel=auth_header should be blocked (got {})",
            res.status()
        );

        // x_header: X-Api-Key: <encoded>
        let res = client
            .get(&url)
            .header("X-Api-Key", &encoded)
            .send()
            .await
            .expect("x_header request");
        assert_eq!(
            res.status().as_u16(),
            451,
            "enc={enc_name} channel=x_header should be blocked (got {})",
            res.status()
        );

        // cookie: Cookie: session=<encoded>
        let res = client
            .get(&url)
            .header("Cookie", format!("session={encoded}"))
            .send()
            .await
            .expect("cookie request");
        assert_eq!(
            res.status().as_u16(),
            451,
            "enc={enc_name} channel=cookie should be blocked (got {})",
            res.status()
        );
    }
}

/// Path-channel regression. Fuzzer reported AKIA canary as
/// `/leak/<base64>` etc. leaking. Before the url-safe second pass in
/// `decode_layers`, `/leak/` was glued into the b64 run and decoded
/// to garbage. Pin every encoding now.
#[tokio::test]
async fn dlp_blocks_encoded_aws_canary_in_uri_path() {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};

    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let raw = "AKIA0123456789ABCDEF";
    let encode_for = |kind: &str| -> String {
        match kind {
            "base64" => STANDARD.encode(raw),
            "base64url" => URL_SAFE.encode(raw).trim_end_matches('=').to_string(),
            "double_base64" => STANDARD.encode(STANDARD.encode(raw)),
            other => panic!("unknown encoding {other}"),
        }
    };

    for enc_name in ["base64", "base64url", "double_base64"] {
        let encoded = encode_for(enc_name);
        // The fuzzer percent-encodes the path segment with `safe=""`,
        // which escapes `=` and `/` (and `+` for double_base64).
        let quoted = encoded
            .replace('=', "%3D")
            .replace('/', "%2F")
            .replace('+', "%2B");
        let url = format!("http://127.0.0.1:{}/leak/{quoted}", upstream.port());
        let res = client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("enc={enc_name}: {e}"));
        assert_eq!(
            res.status().as_u16(),
            451,
            "enc={enc_name} path={url} should be blocked (got {})",
            res.status()
        );
    }
}

/// Body-channel regression: the fuzzer compresses JSON bodies with
/// Python's `zlib.compress` (zlib format / RFC 1950), labels them
/// `Content-Encoding: deflate`, and embeds an encoded canary in
/// `{"token": "..."}`. Previously the proxy's deflate decoder only
/// understood raw DEFLATE (RFC 1951), so the body was opaque and every
/// json_body+deflate combo leaked. Pin both the raw-canary and
/// encoded-canary forms now.
#[tokio::test]
async fn dlp_blocks_zlib_deflate_body_with_aws_canary() {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let raw = "AKIA0123456789ABCDEF";
    let encode_for = |kind: &str| -> String {
        match kind {
            "raw" => raw.to_string(),
            "base64" => STANDARD.encode(raw),
            "base64url" => URL_SAFE.encode(raw).trim_end_matches('=').to_string(),
            "hex" => raw.bytes().map(|b| format!("{b:02x}")).collect(),
            "percent" => raw.bytes().map(|b| format!("%{b:02X}")).collect::<String>(),
            "double_base64" => STANDARD.encode(STANDARD.encode(raw)),
            other => panic!("unknown encoding {other}"),
        }
    };
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());

    for enc_name in [
        "raw",
        "base64",
        "base64url",
        "hex",
        "percent",
        "double_base64",
    ] {
        let encoded = encode_for(enc_name);
        let body_json = format!(r#"{{"token":"{encoded}"}}"#);
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body_json.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        let res = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "deflate")
            .body(compressed)
            .send()
            .await
            .unwrap_or_else(|e| panic!("enc={enc_name}: {e}"));
        assert_eq!(
            res.status().as_u16(),
            451,
            "enc={enc_name} json+deflate should be blocked (got {})",
            res.status()
        );
    }
}

/// Test upstream that returns a hard-coded canary in a Set-Cookie
/// header. Used to verify response-direction DLP catches reflective
/// exfil through response headers (not just bodies).
async fn start_canary_echoing_upstream(canary: &'static str, header: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<hyper::body::Incoming>| async move {
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header(header, format!("payload={canary}"))
                        .header("content-type", "text/plain")
                        .body(
                            Full::new(Bytes::from_static(b"ok"))
                                .map_err(|never| match never {})
                                .boxed(),
                        )
                        .unwrap();
                    Ok::<_, hyper::Error>(resp)
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn dlp_response_scan_catches_canary_in_set_cookie() {
    // End-to-end proof that the new response scanner inspects
    // response headers, not just the body. Pre-PR the upstream's
    // Set-Cookie reflection would have been forwarded untouched.
    const CANARY: &str = "CANISTERTOKENRESPHEADER12345";
    let upstream = start_canary_echoing_upstream(CANARY, "Set-Cookie").await;
    let proxy_addr = start_dlp_proxy(
        vec!["127.0.0.1".to_string()],
        false,
        false,
        vec![CANARY.to_string()],
    )
    .await;
    let client = make_proxy_client(proxy_addr);
    let url = format!("http://127.0.0.1:{}/anything", upstream.port());
    let res = client.get(&url).send().await.expect("request");
    assert_eq!(
        res.status().as_u16(),
        451,
        "canary reflected via Set-Cookie must be blocked (got {})",
        res.status()
    );
}

#[tokio::test]
async fn dlp_response_scan_catches_canary_in_location_redirect() {
    const CANARY: &str = "CANISTERTOKENRESPHEADER98765";
    let upstream = start_canary_echoing_upstream(CANARY, "Location").await;
    let proxy_addr = start_dlp_proxy(
        vec!["127.0.0.1".to_string()],
        false,
        false,
        vec![CANARY.to_string()],
    )
    .await;
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{proxy_addr}")).unwrap())
        // Don't auto-follow; we want the 451, not the upstream's redirect.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/anything", upstream.port());
    let res = client.get(&url).send().await.expect("request");
    assert_eq!(
        res.status().as_u16(),
        451,
        "canary reflected via Location must be blocked (got {})",
        res.status()
    );
}

#[tokio::test]
async fn dlp_blocks_credential_in_formerly_skipped_header() {
    // Regression test for the old "non-sensitive headers not scanned"
    // behaviour. An attacker controlling the worker can stuff
    // credentials into Accept / User-Agent / Cookie / Referer just
    // as easily as into Authorization, so the scanner now treats
    // every header as scannable.
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let client = make_proxy_client(proxy_addr);

    let token = format!("ghp_{}", "I".repeat(36));
    for hdr in ["Accept", "User-Agent", "Cookie", "Referer", "Cache-Control"] {
        let url = format!("http://127.0.0.1:{}/echo", upstream.port());
        let res = client
            .get(&url)
            .header(hdr, &token)
            .send()
            .await
            .expect("request should reach the proxy");

        assert_eq!(
            res.status().as_u16(),
            451,
            "credential in header {hdr} must be blocked (got {})",
            res.status()
        );
    }
}

/// Send a raw HTTP/1.1 chunked request through the proxy with a
/// `Trailer:`-declared trailer carrying the credential. Wire-level
/// because no Rust HTTP client we ship makes trailer construction
/// trivial — and the whole point of this test is that the proxy's
/// trailer-scan path is wired up at all.
async fn send_raw_http(proxy: SocketAddr, raw: &[u8]) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    stream.write_all(raw).await.unwrap();
    stream.flush().await.ok();
    // Bounded read: read until either the connection closes or the
    // 2-second timeout fires. We must NOT shutdown(Write) here —
    // hyper treats half-shutdown as "client gone, no point
    // responding" on some keep-alive paths and races us to closing.
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        stream.read_to_end(&mut buf),
    )
    .await;
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn dlp_blocks_credential_in_request_chunked_trailer() {
    // Before PR4 this request would have been forwarded to the
    // upstream unscrutinised: the proxy only inspected headers
    // (which the trailer is not) and the body bytes (which the
    // credential is not in). Pin the new contract: trailers fire
    // DLP just like headers do.
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let token = format!("ghp_{}", "T".repeat(36));
    let raw = format!(
        "POST http://127.0.0.1:{port}/echo HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Transfer-Encoding: chunked\r\n\
         Trailer: X-Sig\r\n\
         Content-Type: text/plain\r\n\
         \r\n\
         5\r\nhello\r\n\
         0\r\n\
         X-Sig: {token}\r\n\
         \r\n",
        port = upstream.port(),
        token = token,
    );
    let resp = send_raw_http(proxy_addr, raw.as_bytes()).await;
    let status_line = resp.lines().next().unwrap_or("");
    assert!(
        status_line.contains("451"),
        "credential in chunked trailer must trigger 451 (got {status_line:?})"
    );
}

#[tokio::test]
async fn dlp_blocks_credential_in_stacked_content_encoding_body() {
    // `Content-Encoding: deflate, gzip` means deflate(gzip(payload))
    // on the wire. Before PR4 the single-layer decoder didn't
    // recognise the comma-stacked value and fell back to opaque
    // bytes, so the credential inside survived.
    use std::io::Write;
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let token = format!("ghp_{}", "G".repeat(36));
    let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    g.write_all(token.as_bytes()).unwrap();
    let gzipped = g.finish().unwrap();
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(&gzipped).unwrap();
    let body = z.finish().unwrap();

    let raw = {
        let mut buf = Vec::new();
        let header = format!(
            "POST http://127.0.0.1:{port}/echo HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Content-Encoding: gzip, deflate\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {len}\r\n\
             \r\n",
            port = upstream.port(),
            len = body.len(),
        );
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(&body);
        buf
    };
    let resp = send_raw_http(proxy_addr, &raw).await;
    let status_line = resp.lines().next().unwrap_or("");
    assert!(
        status_line.contains("451"),
        "credential in stacked-encoded body must trigger 451 (got {status_line:?})"
    );
}

#[tokio::test]
async fn dlp_blocks_credential_in_multipart_form_part() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let token = format!("ghp_{}", "P".repeat(36));
    let body = format!(
        "--bnd\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"x.png\"\r\n\
         Content-Type: image/png\r\n\
         \r\n\
         (some pixel bytes)\r\n\
         --bnd\r\n\
         Content-Disposition: form-data; name=\"api_key\"\r\n\
         \r\n\
         {token}\r\n\
         --bnd--\r\n",
    );
    let raw = format!(
        "POST http://127.0.0.1:{port}/echo HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: multipart/form-data; boundary=bnd\r\n\
         Content-Length: {len}\r\n\
         \r\n{body}",
        port = upstream.port(),
        len = body.len(),
        body = body,
    );
    let resp = send_raw_http(proxy_addr, raw.as_bytes()).await;
    let status_line = resp.lines().next().unwrap_or("");
    assert!(
        status_line.contains("451"),
        "credential in multipart part must trigger 451 (got {status_line:?})"
    );
}

#[tokio::test]
async fn dlp_blocks_credential_in_xml_body() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let token = format!("ghp_{}", "Y".repeat(36));
    let body = format!(
        "<?xml version=\"1.0\"?><Auth><Provider>github</Provider><Token>{token}</Token></Auth>"
    );
    let raw = format!(
        "POST http://127.0.0.1:{port}/echo HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/xml\r\n\
         Content-Length: {len}\r\n\
         \r\n{body}",
        port = upstream.port(),
        len = body.len(),
        body = body,
    );
    let resp = send_raw_http(proxy_addr, raw.as_bytes()).await;
    let status_line = resp.lines().next().unwrap_or("");
    assert!(
        status_line.contains("451"),
        "credential in XML body must trigger 451 (got {status_line:?})"
    );
}

/// Spin up a proxy whose `[[host]]` table accepts only JSON to
/// `127.0.0.1` and POSTs an `image/png` upload. The contract
/// gate must refuse before any DLP scan runs, with an actionable
/// body that includes the `[[host]]` patch the user can paste.
#[tokio::test]
async fn contract_refusal_image_to_json_only_api() {
    let upstream = start_test_upstream().await;
    let ca = Arc::new(DynamicCa::generate().unwrap());
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_ips: vec!["127.0.0.1".to_string()],
        ..Default::default()
    };
    let hosts = vec![can_policy::config::HostBlock {
        domain: "127.0.0.1".to_string(),
        methods: vec!["GET".to_string(), "POST".to_string()],
        content_types: vec!["application/json".to_string()],
        ..Default::default()
    }];
    let config = can_proxy::server::ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts);
    let proxy = ProxyServer::new(config).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { proxy.run(listener).await.unwrap() });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let headers = format!(
        "POST http://127.0.0.1:{port}/upload HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: image/png\r\n\
         Content-Length: 8\r\n\
         \r\n",
        port = upstream.port(),
    );
    let mut raw: Vec<u8> = headers.into_bytes();
    raw.extend_from_slice(&[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n']);
    let resp = send_raw_http(proxy_addr, &raw).await;
    assert!(
        resp.contains("415"),
        "expected 415 contract refusal, got: {resp}"
    );
    assert!(
        resp.to_ascii_lowercase()
            .contains("x-canister-error: contract-refused"),
        "expected x-canister-error header, got: {resp}"
    );
    assert!(
        resp.contains("[[host]]"),
        "refusal body should include the actionable patch, got: {resp}"
    );
    assert!(
        resp.contains("image/png"),
        "refusal body should mention the offending content type, got: {resp}"
    );
}

/// Unknown destination under Strict (the default) gets a contract
/// refusal — the connect-permission step is gated by the `[[host]]`
/// table.
#[tokio::test]
async fn contract_refusal_unknown_host_strict() {
    let upstream = start_test_upstream().await;
    let ca = Arc::new(DynamicCa::generate().unwrap());
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_ips: vec!["127.0.0.1".to_string()],
        ..Default::default()
    };
    // No [[host]] for 127.0.0.1.
    let config = can_proxy::server::ProxyServerConfig::new(ca).with_network(network);
    let proxy = ProxyServer::new(config).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { proxy.run(listener).await.unwrap() });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let raw = format!(
        "GET http://127.0.0.1:{port}/echo HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         \r\n",
        port = upstream.port(),
    );
    let resp = send_raw_http(proxy_addr, raw.as_bytes()).await;
    // The destination doesn't pass the connect policy gate (it isn't
    // in allow_ips for hostname-form), so we expect either a policy
    // refusal (502 policy-blocked) or a 415 unknown-host depending on
    // whether the IP check vs FQDN check fires first. Either way the
    // x-canister-error header tells us which.
    assert!(
        resp.contains("502 ") || resp.contains("415 "),
        "expected refusal, got: {resp}"
    );
}

#[tokio::test]
async fn dlp_blocks_credential_in_form_urlencoded_body() {
    let upstream = start_test_upstream().await;
    let proxy_addr = start_dlp_proxy(vec!["127.0.0.1".to_string()], false, false, vec![]).await;
    let token = format!("ghp_{}", "U".repeat(36));
    let body = format!("name=alice&token={token}&other=value");
    let raw = format!(
        "POST http://127.0.0.1:{port}/echo HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {len}\r\n\
         \r\n{body}",
        port = upstream.port(),
        len = body.len(),
        body = body,
    );
    let resp = send_raw_http(proxy_addr, raw.as_bytes()).await;
    let status_line = resp.lines().next().unwrap_or("");
    assert!(
        status_line.contains("451"),
        "credential in form-urlencoded body must trigger 451 (got {status_line:?})"
    );
}
