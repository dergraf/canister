//! The session entropy budget across a reasoning model's tool loop
//! (ADR-0020), through the proxy: each request resends the whole
//! conversation plus one new ~1 KB signed thinking block.

use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use can_policy::config::{DlpConfig, EgressMode, HostBlock, NetworkConfig};
use can_proxy::ca::DynamicCa;
use can_proxy::server::{ProxyServer, ProxyServerConfig};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reqwest::{Client, Proxy};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

const PROVIDER: &str = "api.provider.mock.internal";
const TURNS: usize = 20;
const SESSION_BUDGET: u64 = 8 * 1024;
const PROVIDER_BUDGET: u64 = 64 * 1024;

async fn start_mock() -> SocketAddr {
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
                    let _ = req.into_body().collect().await;
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(
                                Full::new(bytes::Bytes::from_static(b"{\"ok\":true}"))
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

fn provider_block(port: u16, session_entropy_budget: Option<u64>) -> HostBlock {
    HostBlock {
        domain: PROVIDER.to_string(),
        upstream: Some(format!("loopback:{port}")),
        allow_credentials: vec!["anthropic_key".to_string()],
        session_entropy_budget,
        ..Default::default()
    }
}

async fn serve(host: HostBlock) -> SocketAddr {
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_host_loopback: true,
        dlp: Some(DlpConfig {
            enabled: Some(true),
            session_entropy_budget: Some(SESSION_BUDGET),
            ..Default::default()
        }),
        ..Default::default()
    };
    let config = ProxyServerConfig::new(Arc::new(DynamicCa::generate().expect("ca")))
        .with_network(network)
        .with_hosts(vec![host])
        .with_host_loopback_target("127.0.0.1".parse().expect("ip"));
    let proxy = ProxyServer::new(config).expect("proxy");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = proxy.run(listener).await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    addr
}

/// Deterministic high-entropy bytes: a SHA-256 chain.
fn pseudo_random(seed: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block = Sha256::digest(seed.as_bytes());
    while out.len() < len {
        out.extend_from_slice(&block);
        block = Sha256::digest(block);
    }
    out.truncate(len);
    out
}

fn thinking_turn(turn: usize) -> String {
    let signature = base64::engine::general_purpose::STANDARD
        .encode(pseudo_random(&format!("signature {turn}"), 1024));
    format!(
        r#"{{"role":"assistant","content":[{{"type":"thinking","thinking":"Read the next file.","signature":"{signature}"}},{{"type":"tool_use","name":"read_file","input":{{"path":"src/module_{turn}.rs"}}}}]}},{{"role":"user","content":"ok"}},"#
    )
}

/// Run the tool loop; returns the status of every turn's request.
async fn tool_loop(proxy: SocketAddr) -> Vec<(StatusCode, Option<String>)> {
    let client = Client::builder()
        .proxy(Proxy::all(format!("http://{proxy}")).expect("proxy url"))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client");
    let mut history = String::new();
    let mut statuses = Vec::new();
    for turn in 0..TURNS {
        history.push_str(&thinking_turn(turn));
        let body = format!(
            r#"{{"model":"reasoning","messages":[{{"role":"user","content":"Fix the failing test."}},{history}]}}"#
        );
        let response = client
            .post(format!("https://{PROVIDER}/v1/messages"))
            .header("content-type", "application/json")
            .header("x-api-key", "test-key")
            .body(body)
            .send()
            .await
            .expect("request");
        let error = response
            .headers()
            .get("x-canister-error")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        statuses.push((response.status(), error));
    }
    statuses
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provider_with_a_per_host_budget_completes_the_tool_loop() {
    let mock = start_mock().await;
    let proxy = serve(provider_block(mock.port(), Some(PROVIDER_BUDGET))).await;

    for (turn, (status, error)) in tool_loop(proxy).await.into_iter().enumerate() {
        assert_eq!(status, StatusCode::OK, "turn {turn}: {error:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_per_host_budget_the_session_default_still_applies() {
    let mock = start_mock().await;
    let proxy = serve(provider_block(mock.port(), None)).await;

    let statuses = tool_loop(proxy).await;
    let blocked = statuses
        .iter()
        .position(|(status, _)| status.as_u16() == 451)
        .expect("the 8 KiB default blocks twenty new signatures");
    assert!(
        statuses[..blocked]
            .iter()
            .all(|(status, _)| *status == StatusCode::OK),
        "{statuses:?}"
    );
    assert_eq!(statuses[blocked].1.as_deref(), Some("dlp-blocked"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_per_host_budget_without_credential_scope_is_not_honoured() {
    let mock = start_mock().await;
    let host = HostBlock {
        allow_credentials: Vec::new(),
        ..provider_block(mock.port(), Some(PROVIDER_BUDGET))
    };
    let proxy = serve(host).await;

    let statuses = tool_loop(proxy).await;
    assert!(
        statuses.iter().any(|(status, _)| status.as_u16() == 451),
        "{statuses:?}"
    );
}
