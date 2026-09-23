//! `[[host]] upstream = "loopback:<port>"` (ADR-0013): the sandboxed
//! workload calls `https://claims.mock.internal/...` as usual, the proxy
//! terminates TLS with its dynamic CA, applies the contract, and forwards
//! to a plain-HTTP service on the host's loopback.

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

const MOCK_HOST: &str = "claims.mock.internal";

/// Plain-HTTP mock: reports the path it was called on and whether TLS was
/// involved (it never is — the hop to the mock is in the clear).
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
                    let host = req
                        .headers()
                        .get(hyper::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("-")
                        .to_string();
                    let path = req.uri().path().to_string();
                    let body = format!("{{\"mock\":true,\"host\":\"{host}\",\"path\":\"{path}\"}}");
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(
                                Full::new(bytes::Bytes::from(body))
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

fn mock_host_block(port: u16, methods: &[&str]) -> HostBlock {
    HostBlock {
        domain: MOCK_HOST.to_string(),
        methods: methods.iter().map(|m| m.to_string()).collect(),
        upstream: Some(format!("loopback:{port}")),
        ..Default::default()
    }
}

fn proxy_config(hosts: Vec<HostBlock>, with_loopback_target: bool) -> ProxyServerConfig {
    let ca = Arc::new(DynamicCa::generate().expect("ca"));
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_host_loopback: true,
        ..Default::default()
    };
    let config = ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(hosts);

    if with_loopback_target {
        // In a real run this is the in-netns gateway pasta maps to the
        // host's 127.0.0.1; in-process, loopback is already the host.
        config.with_host_loopback_target("127.0.0.1".parse().expect("ip"))
    } else {
        config
    }
}

async fn serve(config: ProxyServerConfig) -> SocketAddr {
    let proxy = ProxyServer::new(config).expect("proxy");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = proxy.run(listener).await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    addr
}

fn tls_client(proxy_addr: SocketAddr) -> Client {
    Client::builder()
        .proxy(Proxy::all(format!("http://{proxy_addr}")).expect("proxy url"))
        // The proxy MITMs with a CA generated for this run.
        .danger_accept_invalid_certs(true)
        .build()
        .expect("client")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_https_call_to_a_routed_host_reaches_the_local_mock() {
    let mock = start_mock().await;
    let proxy_addr = serve(proxy_config(vec![mock_host_block(mock.port(), &[])], true)).await;

    let response = tls_client(proxy_addr)
        .get(format!("https://{MOCK_HOST}/claims/42"))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.expect("body");
    assert!(body.contains("\"mock\":true"), "{body}");
    assert!(
        body.contains(&format!("\"host\":\"{MOCK_HOST}\"")),
        "the mock still sees the original host name: {body}"
    );
    assert!(body.contains("\"path\":\"/claims/42\""), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn contracts_still_apply_to_a_routed_host() {
    let mock = start_mock().await;
    let proxy_addr = serve(proxy_config(
        vec![mock_host_block(mock.port(), &["GET"])],
        true,
    ))
    .await;

    let refused = tls_client(proxy_addr)
        .post(format!("https://{MOCK_HOST}/claims"))
        .body("{}")
        .send()
        .await
        .expect("request");

    assert_eq!(
        refused.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "the contract gate runs before the route"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_without_a_route_is_unaffected() {
    let mock = start_mock().await;
    let mut hosts = vec![mock_host_block(mock.port(), &[])];
    hosts.push(HostBlock {
        domain: "unrouted.mock.internal".to_string(),
        ..Default::default()
    });
    let proxy_addr = serve(proxy_config(hosts, true)).await;

    // No route and no DNS entry for this name: the request fails at the
    // dial, not silently at the mock.
    let result = tls_client(proxy_addr)
        .get("https://unrouted.mock.internal/")
        .send()
        .await;

    match result {
        Ok(response) => assert_eq!(
            response.status(),
            StatusCode::BAD_GATEWAY,
            "an unrouted host must not reach the mock"
        ),
        Err(_) => { /* the tunnel failed outright, which is also fine */ }
    }
}

#[test]
fn a_route_without_host_loopback_is_refused_at_startup() {
    let config = proxy_config(vec![mock_host_block(4101, &[])], false);

    let err = match ProxyServer::new(config) {
        Err(err) => err,
        Ok(_) => panic!("a route with no loopback target must not start"),
    };

    let message = err.to_string();
    assert!(message.contains("[unsafe] host_loopback"), "{message}");
    assert!(message.contains(MOCK_HOST), "{message}");
}

#[test]
fn a_malformed_upstream_is_refused_at_startup() {
    let hosts = vec![HostBlock {
        domain: MOCK_HOST.to_string(),
        upstream: Some("localhost:4101".to_string()),
        ..Default::default()
    }];
    let config = proxy_config(hosts, true);

    let err = match ProxyServer::new(config) {
        Err(err) => err,
        Ok(_) => panic!("a malformed upstream must not start"),
    };

    assert!(err.to_string().contains("loopback:<port>"), "{err}");
}

#[test]
fn port_zero_is_not_a_valid_route() {
    let config = proxy_config(vec![mock_host_block(0, &[])], true);

    assert!(
        ProxyServer::new(config).is_err(),
        "port 0 would dial an ephemeral port, never a mock"
    );
}

/// A routed host is dialled on the port the operator configured, not the
/// port the request names.
///
/// The mock is the only thing listening, so a successful round trip is
/// proof the route won: a dial to 8443 on the host loopback would find
/// nothing. This is the invariant that keeps a routed host from becoming
/// a way for the workload to pick a host-local port.
#[tokio::test(flavor = "multi_thread")]
async fn a_routed_host_ignores_the_port_the_workload_asks_for() {
    let mock = start_mock().await;
    let config = proxy_config(vec![mock_host_block(mock.port(), &["GET"])], true);
    let proxy_addr = serve(config).await;

    let response = tls_client(proxy_addr)
        .get(format!("https://{MOCK_HOST}:8443/claims/42"))
        .send()
        .await
        .expect("request");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .text()
            .await
            .expect("body")
            .contains("\"path\":\"/claims/42\""),
        "the configured loopback port must win over the requested one"
    );
}

/// Routing to a local mock is only safe when every request is mediated.
///
/// With `egress` anything other than `proxy-only` — `direct`, say — a
/// CONNECT takes the
/// passthrough path: no TLS termination, no contract, no DLP, no
/// capture. A route that hands the workload an unmediated pipe to a
/// host-local service is not the feature ADR-0013 describes, so refuse
/// it where every other undialable route is refused — at startup.
#[test]
fn a_route_without_proxy_only_egress_is_refused_at_startup() {
    let ca = Arc::new(DynamicCa::generate().expect("ca"));
    let network = NetworkConfig {
        egress: Some(EgressMode::Direct),
        allow_host_loopback: true,
        ..Default::default()
    };
    let config = ProxyServerConfig::new(ca)
        .with_network(network)
        .with_hosts(vec![mock_host_block(4102, &[])])
        .with_host_loopback_target("127.0.0.1".parse().expect("ip"));

    let err = match ProxyServer::new(config) {
        Err(err) => err,
        Ok(_) => panic!("an unmediated route must not start"),
    };

    let message = err.to_string();
    assert!(message.contains(r#"egress = "proxy""#), "{message}");
    assert!(message.contains("would not be mediated"), "{message}");
    assert!(message.contains(MOCK_HOST), "{message}");
}
