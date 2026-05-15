use bytes::Bytes;
use can_policy::config::{EgressMode, NetworkConfig};
use can_proxy::ca::DynamicCa;
use can_proxy::server::ProxyServer;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::header::{HeaderValue, TE};
use hyper::server::conn::http1;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reqwest::{Client, Proxy};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::sync::Once;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;

static BUILD_PLUGIN_ONCE: Once = Once::new();

fn ensure_test_plugin_built() {
    BUILD_PLUGIN_ONCE.call_once(|| {
        let fixture_dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/test-plugin");
        let status = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg("wasm32-unknown-unknown")
            .current_dir(&fixture_dir)
            .status()
            .expect("failed to execute cargo build for test plugin");
        assert!(status.success(), "building test plugin failed");
    });
}

async fn start_test_proxy(interceptors: HashMap<String, std::path::PathBuf>) -> SocketAddr {
    if !interceptors.is_empty() {
        ensure_test_plugin_built();
    }

    let ca = Arc::new(DynamicCa::generate().unwrap());
    let config = can_proxy::server::ProxyServerConfig::new(ca).with_interceptors(interceptors);
    let proxy = ProxyServer::new(config).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let proxy = Arc::new(proxy);
    tokio::spawn(async move {
        proxy.run(listener).await.unwrap();
    });

    addr
}

async fn start_test_proxy_with_network(
    interceptors: HashMap<String, std::path::PathBuf>,
    network: NetworkConfig,
) -> SocketAddr {
    if !interceptors.is_empty() {
        ensure_test_plugin_built();
    }

    let ca = Arc::new(DynamicCa::generate().unwrap());
    let config = can_proxy::server::ProxyServerConfig::new(ca)
        .with_interceptors(interceptors)
        .with_network(network);
    let proxy = ProxyServer::new(config).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        proxy.run(listener).await.unwrap();
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    addr
}

async fn start_test_proxy_with_proxy_config(
    interceptors: HashMap<String, std::path::PathBuf>,
    proxy_config: can_policy::config::ProxyConfig,
    strict: bool,
) -> SocketAddr {
    if !interceptors.is_empty() {
        ensure_test_plugin_built();
    }

    let ca = Arc::new(DynamicCa::generate().unwrap());
    let config = can_proxy::server::ProxyServerConfig::new(ca)
        .with_interceptors(interceptors)
        .with_proxy_config(proxy_config)
        .with_strict(strict);
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
                    if req.uri().path() == "/inspect" {
                        let seen_header = req
                            .headers()
                            .get("x-canister-test")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("none")
                            .to_string();
                        let bytes = req.into_body().collect().await.unwrap().to_bytes();
                        let body = format!(
                            "body={};req_header={}",
                            String::from_utf8_lossy(&bytes),
                            seen_header
                        );
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain")
                            .body(
                                Full::new(Bytes::from(body))
                                    .map_err(|never| match never {})
                                    .boxed(),
                            )
                            .unwrap();
                        return Ok::<_, hyper::Error>(resp);
                    }

                    if req.uri().path() == "/headers" {
                        let added = req
                            .headers()
                            .get("x-added-by-proxy")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("missing");
                        let removed = req.headers().contains_key("x-remove-me");

                        let body = format!("added={added};removed={removed}");
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain")
                            .body(
                                Full::new(Bytes::from(body))
                                    .map_err(|never| match never {})
                                    .boxed(),
                            )
                            .unwrap();
                        return Ok::<_, hyper::Error>(resp);
                    }

                    if req.uri().path() == "/echo-evil" {
                        let evil = req
                            .headers()
                            .get("x-evil")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("missing")
                            .to_string();
                        let smuggled = req
                            .headers()
                            .get("set-cookie")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("missing")
                            .to_string();
                        let body = format!("x_evil={evil};set_cookie={smuggled}");
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain")
                            .body(
                                Full::new(Bytes::from(body))
                                    .map_err(|never| match never {})
                                    .boxed(),
                            )
                            .unwrap();
                        return Ok::<_, hyper::Error>(resp);
                    }

                    if req.uri().path() == "/echo" {
                        let buffer_response = req
                            .headers()
                            .get("x-canister-buffer-response")
                            .and_then(|v| v.to_str().ok())
                            .map(|v| v.eq_ignore_ascii_case("true"))
                            .unwrap_or(false);
                        let bytes = req.into_body().collect().await.unwrap().to_bytes();
                        let mut resp_builder = Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/plain");
                        if buffer_response {
                            resp_builder = resp_builder.header("x-canister-buffer", "true");
                        }

                        let resp = resp_builder
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

async fn start_chunked_test_upstream() -> (SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));

        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let sent = sent.clone();
            async move {
                let buffer_response = req
                    .headers()
                    .get("x-canister-buffer-response")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                let mut body = req.into_body();
                let mut collected = String::new();
                while let Some(frame) = body.frame().await {
                    let frame = frame.unwrap();
                    if let Ok(data) = frame.into_data() {
                        collected.push_str(&String::from_utf8_lossy(&data));
                    }
                }

                if let Some(sender) = sent.lock().unwrap().take() {
                    let _ = sender.send(collected.clone());
                }

                let (resp_tx, resp_rx) = tokio::sync::mpsc::channel::<
                    Result<hyper::body::Frame<Bytes>, hyper::Error>,
                >(8);
                tokio::spawn(async move {
                    let _ = resp_tx
                        .send(Ok(hyper::body::Frame::data(Bytes::from("resp-part-1"))))
                        .await;
                    let _ = resp_tx
                        .send(Ok(hyper::body::Frame::data(Bytes::from("resp-part-2"))))
                        .await;
                });
                let stream = ReceiverStream::new(resp_rx);
                let body: BoxBody<Bytes, hyper::Error> = StreamBody::new(stream).boxed();

                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .header(
                        "x-canister-buffer",
                        if buffer_response { "true" } else { "false" },
                    )
                    .body(body)
                    .unwrap();
                Ok::<_, hyper::Error>(resp)
            }
        });

        if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
            panic!("chunked upstream server error: {err}");
        }
    });

    (addr, rx)
}

async fn start_trailers_test_upstream() -> (SocketAddr, oneshot::Receiver<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));

        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let sent = sent.clone();
            async move {
                let mut body = req.into_body();
                let mut req_trailer_value = None;
                while let Some(frame) = body.frame().await {
                    let frame = frame.unwrap();
                    if let Ok(trailers) = frame.into_trailers() {
                        req_trailer_value = trailers
                            .get("x-original-trailer")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                    }
                }

                if let Some(sender) = sent.lock().unwrap().take() {
                    let _ = sender.send(req_trailer_value);
                }

                let (resp_tx, resp_rx) = tokio::sync::mpsc::channel::<
                    Result<hyper::body::Frame<Bytes>, hyper::Error>,
                >(8);
                tokio::spawn(async move {
                    let _ = resp_tx
                        .send(Ok(hyper::body::Frame::data(Bytes::from("resp"))))
                        .await;
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert("x-upstream-trailer", HeaderValue::from_static("present"));
                    let _ = resp_tx
                        .send(Ok(hyper::body::Frame::trailers(trailers)))
                        .await;
                });

                let stream = ReceiverStream::new(resp_rx);
                let body: BoxBody<Bytes, hyper::Error> = StreamBody::new(stream).boxed();
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .header("trailer", "x-upstream-trailer")
                    .body(body)
                    .unwrap();
                Ok::<_, hyper::Error>(resp)
            }
        });

        if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
            panic!("trailers upstream server error: {err}");
        }
    });

    (addr, rx)
}

async fn start_h2c_test_upstream() -> (SocketAddr, oneshot::Receiver<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let io = hyper_util::rt::TokioIo::new(stream);
        let sent = std::sync::Arc::new(std::sync::Mutex::new(Some(tx)));

        let service = service_fn(move |req: Request<hyper::body::Incoming>| {
            let sent = sent.clone();
            async move {
                if let Some(sender) = sent.lock().unwrap().take() {
                    let _ = sender.send(req.version() == hyper::Version::HTTP_2);
                }

                let mut body = req.into_body();
                while let Some(frame) = body.frame().await {
                    let _ = frame.unwrap();
                }

                let (resp_tx, resp_rx) = tokio::sync::mpsc::channel::<
                    Result<hyper::body::Frame<Bytes>, hyper::Error>,
                >(8);
                tokio::spawn(async move {
                    let _ = resp_tx
                        .send(Ok(hyper::body::Frame::data(Bytes::from("h2-part-1"))))
                        .await;
                    let _ = resp_tx
                        .send(Ok(hyper::body::Frame::data(Bytes::from("h2-part-2"))))
                        .await;
                    let mut trailers = hyper::HeaderMap::new();
                    trailers.insert("x-upstream-trailer", HeaderValue::from_static("present"));
                    let _ = resp_tx
                        .send(Ok(hyper::body::Frame::trailers(trailers)))
                        .await;
                });

                let stream = ReceiverStream::new(resp_rx);
                let body: BoxBody<Bytes, hyper::Error> = StreamBody::new(stream).boxed();
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .body(body)
                    .unwrap();
                Ok::<_, hyper::Error>(resp)
            }
        });

        if let Err(err) = http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(io, service)
            .await
        {
            panic!("h2c upstream server error: {err:?}");
        }
    });

    (addr, rx)
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
    assert_eq!(
        res.headers()
            .get("x-canister-test")
            .and_then(|v| v.to_str().ok()),
        Some("response-seen")
    );
    let body = res.text().await.unwrap();
    assert!(body.contains("\"url\": \"http://httpbin.org/get\""));
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
    assert_eq!(
        res.headers()
            .get("x-canister-test")
            .and_then(|v| v.to_str().ok()),
        Some("response-seen")
    );
    let body = res.text().await.unwrap();
    assert!(body.contains("\"url\": \"https://httpbin.org/get\""));
}

#[tokio::test]
async fn test_http_intercept_wasm_body_mutation_local() {
    let upstream = start_test_upstream().await;

    let mut interceptors = HashMap::new();
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm");
    interceptors.insert("127.0.0.1".to_string(), wasm_path);

    let proxy_addr = start_test_proxy(interceptors).await;
    let proxy_url = format!("http://{}", proxy_addr);

    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .post(url)
        .header("x-canister-buffer", "true")
        .body("hello-proxy")
        .send()
        .await
        .expect("failed to send request through proxy");

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("x-canister-test")
            .and_then(|v| v.to_str().ok()),
        Some("response-seen")
    );

    let body = res.text().await.unwrap();
    assert_eq!(body, "HELLO-PROXY|RQCHUNK|REQ-EOS|RSCHUNK|RESP-EOS");
}

#[tokio::test]
async fn test_http_intercept_wasm_streaming_multi_chunk() {
    let (upstream, seen_req_body) = start_chunked_test_upstream().await;

    let mut interceptors = HashMap::new();
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm");
    interceptors.insert("127.0.0.1".to_string(), wasm_path);

    let proxy_addr = start_test_proxy(interceptors).await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/stream", upstream.port());
    let res = client
        .post(url)
        .body("alpha-beta")
        .send()
        .await
        .expect("streaming proxy request failed");

    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert_eq!(body, "resp-part-1|RSCHUNKresp-part-2|RSCHUNK|RESP-EOS");

    let seen = seen_req_body
        .await
        .expect("did not receive upstream seen body");
    assert_eq!(seen, "ALPHA-BETA|RQCHUNK|REQ-EOS");
}

#[tokio::test]
async fn test_http_intercept_wasm_buffering_sets_content_length() {
    let upstream = start_test_upstream().await;

    let mut interceptors = HashMap::new();
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm");
    interceptors.insert("127.0.0.1".to_string(), wasm_path);

    let proxy_addr = start_test_proxy(interceptors).await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .post(url)
        .header("x-canister-buffer", "true")
        .header("x-canister-buffer-response", "true")
        .body("tiny")
        .send()
        .await
        .expect("buffered request failed");

    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.headers().get("content-length").is_some());
    assert_eq!(res.headers().get("transfer-encoding"), None);

    let body = res.text().await.unwrap();
    assert_eq!(body, "TINY|RQCHUNK|REQ-EOS|RSCHUNK|RESP-EOS");
}

#[tokio::test]
async fn test_http_intercept_wasm_header_injection_and_removal() {
    let upstream = start_test_upstream().await;

    let mut interceptors = HashMap::new();
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm");
    interceptors.insert("127.0.0.1".to_string(), wasm_path);

    let proxy_addr = start_test_proxy(interceptors).await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/headers", upstream.port());
    let res = client
        .get(url)
        .header("x-canister-mode", "inject-remove")
        .header("x-canister-buffer-response", "true")
        .header("x-remove-me", "please")
        .send()
        .await
        .expect("header mutation request failed");

    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert_eq!(body, "added=yes;removed=false|RSCHUNK|RESP-EOS");
}

#[tokio::test]
async fn test_http_intercept_wasm_streaming_uses_chunked_transfer_encoding() {
    let (upstream, _) = start_chunked_test_upstream().await;

    let mut interceptors = HashMap::new();
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm");
    interceptors.insert("127.0.0.1".to_string(), wasm_path);

    let proxy_addr = start_test_proxy(interceptors).await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/stream", upstream.port());
    let res = client
        .post(url)
        .body("stream-verify")
        .send()
        .await
        .expect("stream request failed");

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get("content-length"), None);
    assert_eq!(
        res.headers()
            .get("transfer-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("chunked")
    );
}

#[tokio::test]
async fn test_http_intercept_wasm_response_trailers_mutation() {
    let (upstream, seen_req_trailer) = start_trailers_test_upstream().await;

    let mut interceptors = HashMap::new();
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm");
    interceptors.insert("127.0.0.1".to_string(), wasm_path);

    let proxy_addr = start_test_proxy(interceptors).await;
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

    let (req_tx, req_rx) =
        tokio::sync::mpsc::channel::<Result<hyper::body::Frame<Bytes>, hyper::Error>>(8);
    tokio::spawn(async move {
        let _ = req_tx
            .send(Ok(hyper::body::Frame::data(Bytes::from("hello"))))
            .await;
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("x-original-trailer", HeaderValue::from_static("client"));
        let _ = req_tx
            .send(Ok(hyper::body::Frame::trailers(trailers)))
            .await;
    });

    let uri = format!("http://127.0.0.1:{}/trailers", upstream.port())
        .parse::<hyper::Uri>()
        .unwrap();
    let body = StreamBody::new(ReceiverStream::new(req_rx)).boxed();
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(TE, HeaderValue::from_static("trailers"))
        .header("trailer", HeaderValue::from_static("x-original-trailer"))
        .body(body)
        .unwrap();

    let mut res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let mut saw_resp_trailer = None;
    while let Some(frame) = res.body_mut().frame().await {
        let frame = frame.unwrap();
        if let Ok(trailers) = frame.into_trailers() {
            saw_resp_trailer = trailers
                .get("x-upstream-trailer")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
        }
    }

    let _ = seen_req_trailer.await;
    assert_eq!(saw_resp_trailer.as_deref(), Some("seen"));
}

#[tokio::test]
#[cfg_attr(
    not(feature = "experimental-h2c"),
    ignore = "h2c test disabled unless can-proxy is built with feature `experimental-h2c`"
)]
#[cfg_attr(
    feature = "experimental-h2c",
    ignore = "experimental-h2c enabled but forwarding path still unstable; owner=proxy-team; expiry=2026-07-15"
)]
async fn test_http_intercept_wasm_h2c_upstream_streaming_and_trailers() {
    let (upstream, saw_h2) = start_h2c_test_upstream().await;

    let mut interceptors = HashMap::new();
    let wasm_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm");
    interceptors.insert("127.0.0.1".to_string(), wasm_path);

    let proxy_addr = start_test_proxy(interceptors).await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/h2c", upstream.port());
    let res = client
        .post(url)
        .header("x-canister-buffer", "false")
        .header("x-canister-buffer-response", "false")
        .header("x-canister-upstream-scheme", "h2c")
        .body("h2-input")
        .send()
        .await
        .expect("h2c proxied request failed");

    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert_eq!(body, "h2-part-1|RSCHUNKh2-part-2|RSCHUNK|RESP-EOS");

    let used_h2 = saw_h2.await.expect("upstream did not report protocol");
    assert!(used_h2, "expected proxy->upstream to use HTTP/2");
}

#[tokio::test]
async fn test_proxy_blocks_disallowed_domain_by_network_policy() {
    let upstream = start_test_upstream().await;
    let network = NetworkConfig {
        egress: Some(EgressMode::ProxyOnly),
        allow_domains: vec!["localhost".to_string()],
        ..Default::default()
    };

    let addr = start_test_proxy_with_network(HashMap::new(), network).await;
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
    let proxy_addr = start_test_proxy(HashMap::new()).await;

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

fn test_plugin_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/test-plugin/target/wasm32-unknown-unknown/release/test_plugin.wasm")
}

#[tokio::test]
async fn test_request_body_buffer_limit_returns_413() {
    let upstream = start_test_upstream().await;

    let mut interceptors = HashMap::new();
    interceptors.insert("127.0.0.1".to_string(), test_plugin_path());

    let proxy_config = can_policy::config::ProxyConfig {
        max_buffered_body_bytes: Some(64),
        ..Default::default()
    };

    let proxy_addr = start_test_proxy_with_proxy_config(interceptors, proxy_config, false).await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    // Body well over the 64-byte cap; `x-canister-buffer: true` forces the
    // proxy to fully buffer the request body before forwarding.
    let big_body = vec![b'x'; 4 * 1024];
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .post(url)
        .header("x-canister-buffer", "true")
        .body(big_body)
        .send()
        .await
        .expect("failed to send oversized request through proxy");

    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        res.headers()
            .get("x-canister-error")
            .and_then(|v| v.to_str().ok()),
        Some("body-too-large")
    );
}

#[tokio::test]
async fn test_wasm_hook_timeout_returns_502_in_strict_mode() {
    let upstream = start_test_upstream().await;

    let mut interceptors = HashMap::new();
    interceptors.insert("127.0.0.1".to_string(), test_plugin_path());

    let proxy_config = can_policy::config::ProxyConfig {
        wasm_hook_timeout_ms: Some(50),
        ..Default::default()
    };

    let proxy_addr = start_test_proxy_with_proxy_config(interceptors, proxy_config, true).await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    // Mode "hang" puts the plugin into a tight infinite loop; the proxy's
    // watchdog must cancel it after ~50 ms and return 502.
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(url)
        .header("x-canister-mode", "hang")
        .send()
        .await
        .expect("expected proxy to respond rather than hang");

    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        res.headers()
            .get("x-canister-error")
            .and_then(|v| v.to_str().ok()),
        Some("wasm-timeout")
    );
}

#[tokio::test]
async fn test_strict_mode_wasm_error_returns_502() {
    let upstream = start_test_upstream().await;

    let mut interceptors = HashMap::new();
    interceptors.insert("127.0.0.1".to_string(), test_plugin_path());

    let proxy_addr = start_test_proxy_with_proxy_config(
        interceptors,
        can_policy::config::ProxyConfig::default(),
        true,
    )
    .await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    // Mode "error" causes on_request_headers to return Err. In strict mode
    // the proxy must fail closed with 502 and `x-canister-error: wasm-error`.
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .get(url)
        .header("x-canister-mode", "error")
        .send()
        .await
        .expect("strict-mode plugin error should still produce a response");

    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        res.headers()
            .get("x-canister-error")
            .and_then(|v| v.to_str().ok()),
        Some("wasm-error")
    );
}

#[tokio::test]
async fn test_wasm_crlf_header_is_dropped() {
    let upstream = start_test_upstream().await;

    let mut interceptors = HashMap::new();
    interceptors.insert("127.0.0.1".to_string(), test_plugin_path());

    // Non-strict: the request should succeed; the smuggled CRLF header must
    // be silently dropped before reaching upstream.
    let proxy_addr = start_test_proxy(interceptors).await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{}/echo-evil", upstream.port());
    let res = client
        .get(url)
        .header("x-canister-mode", "crlf-smuggling")
        .send()
        .await
        .expect("CRLF-smuggling request should reach upstream without the evil header");

    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    // Upstream sees neither x-evil nor a smuggled set-cookie. The response
    // body is passed through the test plugin's on_response_body hook which
    // appends |RSCHUNK and |RESP-EOS markers.
    assert!(
        body.starts_with("x_evil=missing;set_cookie=missing"),
        "smuggled headers must not reach upstream; got body: {body:?}"
    );
}

// ============================================================================
// Body-mutation EOS matrix
// ============================================================================
//
// Pins the proxy's behaviour when a Wasm plugin instructs it to buffer
// the response body and that body exceeds the configured cap: proxy
// must return 502 with the upstream-body-too-large marker rather than
// truncating. The mirror cases for plugin-driven request-body
// drop/expand need an ABI extension (request headers in the body-hook
// payload) and are tracked separately.
// ============================================================================

#[tokio::test]
async fn body_mutation_buffered_response_oversize_returns_502() {
    let upstream = start_test_upstream().await;

    let mut interceptors = HashMap::new();
    interceptors.insert("127.0.0.1".to_string(), test_plugin_path());

    // Tiny cap; the upstream's "/echo" reply will easily exceed it.
    let proxy_config = can_policy::config::ProxyConfig {
        max_buffered_body_bytes: Some(8),
        ..Default::default()
    };
    let proxy_addr = start_test_proxy_with_proxy_config(interceptors, proxy_config, false).await;
    let proxy_url = format!("http://{}", proxy_addr);
    let client = Client::builder()
        .proxy(Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();

    // The /echo endpoint echoes the body. With x-canister-buffer-response,
    // upstream returns a `x-canister-buffer: true` header that the test
    // plugin's on_response_headers respects, forcing the proxy to buffer
    // the response body. Body is bigger than the 8-byte limit, so the
    // proxy must return 502 with x-canister-error: upstream-body-too-large.
    let url = format!("http://127.0.0.1:{}/echo", upstream.port());
    let res = client
        .post(url)
        .header("x-canister-buffer-response", "true")
        .body("payload-larger-than-eight-bytes")
        .send()
        .await
        .expect("request reached proxy");

    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        res.headers()
            .get("x-canister-error")
            .and_then(|v| v.to_str().ok()),
        Some("upstream-body-too-large"),
    );
}
