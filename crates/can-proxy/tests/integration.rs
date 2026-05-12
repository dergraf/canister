use can_proxy::ca::DynamicCa;
use can_proxy::server::ProxyServer;
use reqwest::{Client, Proxy};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

async fn start_test_proxy(interceptors: HashMap<String, std::path::PathBuf>) -> SocketAddr {
    let ca = DynamicCa::generate().unwrap();
    let proxy = ProxyServer::new(ca, &interceptors).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let proxy = Arc::new(proxy);
    tokio::spawn(async move {
        proxy.run(listener).await.unwrap();
    });

    addr
}

#[tokio::test]
async fn test_http_passthrough() {
    let addr = start_test_proxy(HashMap::new()).await;
    let proxy_url = format!("http://{}", addr);

    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    // Make an HTTP request
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
    let addr = start_test_proxy(HashMap::new()).await;
    let proxy_url = format!("http://{}", addr);

    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        // Ignore cert errors since we are using passthrough but reqwest might still
        // be weird, wait: for passthrough, the TLS connection is made directly to the destination!
        // So the certificate will be the real one from httpbin.org, not our CA's.
        .build()
        .unwrap();

    // Make an HTTPS request
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
async fn test_http_intercept_wasm() {
    let mut interceptors = HashMap::new();
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm");
    interceptors.insert("httpbin.org".to_string(), wasm_path);

    let addr = start_test_proxy(interceptors).await;
    let proxy_url = format!("http://{}", addr);

    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .danger_accept_invalid_certs(true) // Accept our fake CA
        .build()
        .unwrap();

    let res = client
        .get("http://httpbin.org/get")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    // The WASM plugin returns {"message": "hello from wasm"}
    assert!(body.contains("hello from wasm"));
}

#[tokio::test]
async fn test_https_intercept_wasm() {
    let mut interceptors = HashMap::new();
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm");
    interceptors.insert("httpbin.org".to_string(), wasm_path);

    let addr = start_test_proxy(interceptors).await;
    let proxy_url = format!("http://{}", addr);

    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .danger_accept_invalid_certs(true) // Accept our fake CA
        .build()
        .unwrap();

    let res = client
        .get("https://httpbin.org/get")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), 200);
    let body = res.text().await.unwrap();
    assert!(body.contains("hello from wasm"));
}
