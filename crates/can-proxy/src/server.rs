use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::SizeHint;
use hyper::header::{CONTENT_LENGTH, HOST, HeaderName, HeaderValue, TRANSFER_ENCODING};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tracing::{debug, error, info, warn};

use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::ca::DynamicCa;
use crate::client::{HttpsClient, build_client};
use crate::egress;
use crate::policy::OutboundPolicy;
use crate::wasm::WasmEngine;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CA error: {0}")]
    Ca(#[from] crate::ca::CaError),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("Wasm error: {0}")]
    Wasm(#[from] crate::wasm::WasmError),
}

pub struct ProxyServer {
    ca: Arc<DynamicCa>,
    wasm_engine: Arc<WasmEngine>,
    client: HttpsClient,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
}

impl ProxyServer {
    pub fn new(
        ca: DynamicCa,
        interceptors: &std::collections::HashMap<String, std::path::PathBuf>,
    ) -> Result<Self, ProxyError> {
        let wasm_engine = WasmEngine::new(interceptors)?;
        Ok(Self {
            ca: Arc::new(ca),
            wasm_engine: Arc::new(wasm_engine),
            client: build_client(),
            dns_cache: can_net::dns_cache::DnsCache::new(Duration::from_secs(15)),
            outbound_policy: OutboundPolicy::default(),
        })
    }

    pub fn new_with_arc(
        ca: Arc<DynamicCa>,
        interceptors: &std::collections::HashMap<String, std::path::PathBuf>,
    ) -> Result<Self, ProxyError> {
        let wasm_engine = WasmEngine::new(interceptors)?;
        Ok(Self {
            ca,
            wasm_engine: Arc::new(wasm_engine),
            client: build_client(),
            dns_cache: can_net::dns_cache::DnsCache::new(Duration::from_secs(15)),
            outbound_policy: OutboundPolicy::default(),
        })
    }

    pub fn new_with_policy(
        ca: Arc<DynamicCa>,
        interceptors: &std::collections::HashMap<String, std::path::PathBuf>,
        network: &can_policy::config::NetworkConfig,
    ) -> Result<Self, ProxyError> {
        let wasm_engine = WasmEngine::new(interceptors)?;
        let outbound_policy = OutboundPolicy::from_config(network);

        Ok(Self {
            ca,
            wasm_engine: Arc::new(wasm_engine),
            client: build_client(),
            dns_cache: can_net::dns_cache::DnsCache::new(Duration::from_secs(15)),
            outbound_policy,
        })
    }

    pub async fn run(&self, listener: tokio::net::TcpListener) -> Result<(), ProxyError> {
        info!("Proxy server listening on {}", listener.local_addr()?);

        loop {
            let (stream, _peer_addr) = listener.accept().await?;
            let io = TokioIo::new(stream);

            let ca = self.ca.clone();
            let wasm_engine = self.wasm_engine.clone();
            let client = self.client.clone();
            let dns_cache = self.dns_cache.clone();
            let outbound_policy = self.outbound_policy.clone();
            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            handle_proxy_request(
                                req,
                                ca.clone(),
                                wasm_engine.clone(),
                                client.clone(),
                                dns_cache.clone(),
                                outbound_policy.clone(),
                            )
                        }),
                    )
                    .with_upgrades()
                    .await
                {
                    error!("Failed to serve connection: {:?}", err);
                }
            });
        }
    }
}

async fn handle_proxy_request(
    req: Request<hyper::body::Incoming>,
    ca: Arc<DynamicCa>,
    wasm_engine: Arc<WasmEngine>,
    client: HttpsClient,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        let authority = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let host_name_only = authority.split(':').next().unwrap_or("").to_string();
        let has_interceptor = wasm_engine.has_plugin(&host_name_only);
        debug!("Received CONNECT request for {}", authority);

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if has_interceptor {
                        if let Err(e) = handle_tunnel(
                            upgraded,
                            host_name_only,
                            ca,
                            wasm_engine,
                            client.clone(),
                            dns_cache.clone(),
                        )
                        .await
                        {
                            error!("TLS Tunnel error for {}: {}", authority, e);
                        }
                    } else if let Err(e) = handle_passthrough(
                        upgraded,
                        authority.clone(),
                        dns_cache.clone(),
                        outbound_policy.clone(),
                    )
                    .await
                    {
                        error!("Passthrough error for {}: {}", authority, e);
                    }
                }
                Err(e) => error!("Upgrade error: {}", e),
            }
        });

        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::OK;
        return Ok(resp);
    }

    if crate::websocket::is_websocket_upgrade(&req) {
        return Ok(crate::websocket::not_implemented_ws_bridge().await);
    }

    // For plain HTTP requests
    let host = extract_host(&req);
    if wasm_engine.has_plugin(&host) {
        return handle_inner_request(req, wasm_engine, client.clone(), "http").await;
    }

    // Plain HTTP passthrough
    handle_http_passthrough(req, dns_cache, outbound_policy).await
}

async fn handle_http_passthrough(
    req: Request<hyper::body::Incoming>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let host = req.uri().host().map(|s| s.to_string()).unwrap_or_else(|| {
        req.headers()
            .get(hyper::header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_default()
    });
    let port = req.uri().port_u16().unwrap_or(80);

    match connect_via_cache(&dns_cache, &host, port, &outbound_policy).await {
        Ok(stream) => {
            let io = TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io)
                .await?;

            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    error!("Connection failed: {:?}", err);
                }
            });

            sender
                .send_request(req)
                .await
                .map(|res| res.map(|body| body.boxed()))
        }
        Err(e) => {
            let mut resp = Response::new(full_body(format!("Bad Gateway: {}", e)));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
    }
}

async fn handle_passthrough(
    upgraded: Upgraded,
    target: String,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
) -> Result<(), std::io::Error> {
    debug!("Establishing TCP passthrough for {}", target);
    let (host, port) = split_target_host_port(&target)?;
    let mut server = connect_via_cache(&dns_cache, &host, port, &outbound_policy).await?;
    let mut client = TokioIo::new(upgraded);
    tokio::io::copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
}

async fn handle_inner_request(
    mut req: Request<hyper::body::Incoming>,
    wasm_engine: Arc<WasmEngine>,
    client: HttpsClient,
    default_scheme: &'static str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    debug!("Intercepting request: {} {}", req.method(), req.uri());

    let host = extract_host(&req);
    let has_plugin = wasm_engine.has_plugin(&host);
    let mut buffer_request_body = false;

    if has_plugin {
        let req_headers_json = serde_json::json!({
            "method": req.method().as_str(),
            "uri": req.uri().to_string(),
            "headers": req.headers().iter().map(|(k, v)| (k.as_str(), v.to_str().unwrap_or(""))).collect::<std::collections::HashMap<_, _>>()
        });

        match wasm_engine.execute(
            &host,
            "on_request_headers",
            serde_json::to_vec(&req_headers_json).unwrap_or_default(),
        ) {
            Ok(output) => {
                if let Ok(resp_json) = serde_json::from_slice::<serde_json::Value>(&output) {
                    if let Some(resp) = build_short_circuit_response(&resp_json) {
                        return Ok(resp);
                    }

                    apply_header_mutations(req.headers_mut(), &resp_json);
                    buffer_request_body = should_buffer_body(&resp_json);
                }
            }
            Err(e) => {
                debug!(
                    "Wasm on_request_headers execution failed or not found for {}: {}",
                    host, e
                );
            }
        }

        req.headers_mut().remove(CONTENT_LENGTH);
    }

    let (uri, original_scheme) = match egress::build_upstream_uri(&req, &host, default_scheme) {
        Ok(v) => v,
        Err(err) => {
            error!("{}", err);
            let mut resp = Response::new(full_body("Bad Request"));
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(resp);
        }
    };
    req.headers_mut().remove("x-canister-upstream-scheme");
    *req.uri_mut() = uri;

    let (mut parts, body) = req.into_parts();
    let req_body = if has_plugin && buffer_request_body {
        let collected = body.collect().await?;
        let trailers = collected
            .trailers()
            .cloned()
            .map(|trailers| mutate_trailers(&wasm_engine, &host, "on_request_trailers", trailers));
        let has_trailers = trailers.as_ref().is_some_and(|t| !t.is_empty());
        let mut bytes = collected.to_bytes();
        bytes = mutate_body_chunk_with_eos(&wasm_engine, &host, "on_request_body", bytes, true);

        update_length_headers(&mut parts.headers, bytes.len(), has_trailers);

        single_chunk_body(bytes, trailers)
    } else if has_plugin {
        HookedBody::new(
            body,
            wasm_engine.clone(),
            host.clone(),
            "on_request_body",
            "on_request_trailers",
        )
        .boxed()
    } else {
        body.boxed()
    };
    let mut upstream_req = Request::from_parts(parts, req_body);
    if original_scheme == "h2c" {
        egress::sanitize_h2c_headers(&mut upstream_req);
    }

    let upstream_result: Result<Response<hyper::body::Incoming>, String> =
        egress::forward_request(client.clone(), upstream_req, &original_scheme).await;

    match upstream_result {
        Ok(mut res) => {
            let mut buffer_response_body = false;
            if has_plugin {
                let resp_headers_json = serde_json::json!({
                    "status": res.status().as_u16(),
                    "headers": res.headers().iter().map(|(k, v)| (k.as_str(), v.to_str().unwrap_or(""))).collect::<std::collections::HashMap<_, _>>()
                });

                if let Ok(output) = wasm_engine.execute(
                    &host,
                    "on_response_headers",
                    serde_json::to_vec(&resp_headers_json).unwrap_or_default(),
                ) {
                    if let Ok(resp_json) = serde_json::from_slice::<serde_json::Value>(&output) {
                        if let Some(resp) = build_short_circuit_response(&resp_json) {
                            return Ok(resp);
                        }

                        apply_header_mutations(res.headers_mut(), &resp_json);
                        buffer_response_body = should_buffer_body(&resp_json);
                    }
                }
            }

            let (mut parts, body) = res.into_parts();
            let resp_body: BoxBody<Bytes, hyper::Error> = if has_plugin && buffer_response_body {
                let collected = body.collect().await?;
                let trailers = collected.trailers().cloned().map(|trailers| {
                    mutate_trailers(&wasm_engine, &host, "on_response_trailers", trailers)
                });
                let has_trailers = trailers.as_ref().is_some_and(|t| !t.is_empty());
                let mut bytes = collected.to_bytes();
                bytes = mutate_body_chunk_with_eos(
                    &wasm_engine,
                    &host,
                    "on_response_body",
                    bytes,
                    true,
                );

                update_length_headers(&mut parts.headers, bytes.len(), has_trailers);
                single_chunk_body(bytes, trailers)
            } else if has_plugin {
                parts.headers.remove(CONTENT_LENGTH);
                HookedBody::new(
                    body,
                    wasm_engine,
                    host,
                    "on_response_body",
                    "on_response_trailers",
                )
                .boxed()
            } else {
                body.boxed()
            };
            Ok(Response::from_parts(parts, resp_body))
        }
        Err(e) => {
            error!("Upstream request failed: {}", e);
            let mut resp = Response::new(full_body("Bad Gateway"));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
    }
}

async fn handle_tunnel(
    upgraded: Upgraded,
    host_with_port: String,
    ca: Arc<DynamicCa>,
    wasm_engine: Arc<WasmEngine>,
    client: HttpsClient,
    _dns_cache: can_net::dns_cache::DnsCache,
) -> Result<(), std::io::Error> {
    let host = host_with_port.split(':').next().unwrap_or("").to_string();
    debug!("Establishing TLS tunnel for {}", host);

    let (cert, key) = ca
        .generate_server_cert(&host)
        .map_err(|e| std::io::Error::other(format!("Failed to generate cert: {}", e)))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let io = TokioIo::new(upgraded);
    let tls_stream = tls_acceptor.accept(io).await?;
    let tls_io = TokioIo::new(tls_stream);

    http1::Builder::new()
        .serve_connection(
            tls_io,
            service_fn(move |req| {
                handle_inner_request(req, wasm_engine.clone(), client.clone(), "https")
            }),
        )
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(())
}

fn split_target_host_port(target: &str) -> Result<(String, u16), std::io::Error> {
    let mut split = target.rsplitn(2, ':');
    let port_str = split
        .next()
        .ok_or_else(|| std::io::Error::other("missing port"))?;
    let host = split
        .next()
        .ok_or_else(|| std::io::Error::other("missing host"))?
        .to_string();
    let port = port_str
        .parse::<u16>()
        .map_err(|_| std::io::Error::other("invalid port"))?;
    Ok((host, port))
}

async fn connect_via_cache(
    dns_cache: &can_net::dns_cache::DnsCache,
    host: &str,
    port: u16,
    outbound_policy: &OutboundPolicy,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !outbound_policy.allows_ip_literal(ip) {
            return Err(std::io::Error::other("ip not allowed by policy"));
        }
        return tokio::net::TcpStream::connect((ip, port)).await;
    }

    if !outbound_policy.allows_host(host) {
        return Err(std::io::Error::other("domain not allowed by policy"));
    }

    let cache = dns_cache.clone();
    let host_owned = host.to_string();
    let ips = tokio::task::spawn_blocking(move || cache.resolve_cached_or_lookup(&host_owned))
        .await
        .map_err(|e| std::io::Error::other(format!("dns lookup task failed: {e}")))?
        .ok_or_else(|| std::io::Error::other("dns lookup failed"))?;

    let mut last_err: Option<std::io::Error> = None;
    for ip in ips {
        if !outbound_policy.allows_ip(ip) {
            continue;
        }
        match tokio::net::TcpStream::connect((ip, port)).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| std::io::Error::other("all resolved IPs failed")))
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn extract_host<B>(req: &Request<B>) -> String {
    req.uri().host().map(str::to_string).unwrap_or_else(|| {
        req.headers()
            .get(HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_default()
    })
}

fn build_short_circuit_response(
    hook_response: &serde_json::Value,
) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
    if hook_response.get("action").and_then(|a| a.as_str()) != Some("Respond") {
        return None;
    }

    let mut builder = Response::builder();
    if let Some(status) = hook_response.get("status").and_then(|s| s.as_u64()) {
        builder = builder.status(status as u16);
    }

    if let Some(headers) = hook_response.get("headers").and_then(|h| h.as_object()) {
        for (k, v) in headers {
            if let Some(v_str) = v.as_str() {
                builder = builder.header(k, v_str);
            }
        }
    }

    let body = hook_response
        .get("body")
        .and_then(|b| b.as_str())
        .and_then(|b64| base64::prelude::BASE64_STANDARD.decode(b64).ok())
        .unwrap_or_default();

    Some(builder.body(full_body(body)).unwrap_or_else(|_| {
        let mut resp = Response::new(full_body("Internal Server Error"));
        *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        resp
    }))
}

fn apply_header_mutations(headers: &mut hyper::HeaderMap, hook_response: &serde_json::Value) {
    let Some(mutations) = hook_response.get("mutations") else {
        return;
    };

    if let Some(remove_headers) = mutations.get("remove_headers").and_then(|h| h.as_array()) {
        for name in remove_headers.iter().filter_map(|h| h.as_str()) {
            if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) {
                headers.remove(header_name);
            }
        }
    }

    if let Some(set_headers) = mutations.get("set_headers").and_then(|h| h.as_object()) {
        for (name, value) in set_headers {
            let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            let Some(value) = value.as_str() else {
                continue;
            };
            let Ok(header_value) = HeaderValue::from_str(value) else {
                continue;
            };
            headers.insert(header_name, header_value);
        }
    }
}

fn should_buffer_body(hook_response: &serde_json::Value) -> bool {
    hook_response
        .get("buffer_body")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn update_length_headers(headers: &mut hyper::HeaderMap, body_len: usize, has_trailers: bool) {
    headers.remove(CONTENT_LENGTH);

    if has_trailers {
        headers.remove(TRANSFER_ENCODING);
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        return;
    }

    if let Ok(value) = HeaderValue::from_str(&body_len.to_string()) {
        headers.insert(CONTENT_LENGTH, value);
    }
    headers.remove(TRANSFER_ENCODING);
}

fn mutate_body_chunk_with_eos(
    wasm_engine: &WasmEngine,
    host: &str,
    function: &str,
    chunk: Bytes,
    end_of_stream: bool,
) -> Bytes {
    let payload = serde_json::json!({
        "body": base64::prelude::BASE64_STANDARD.encode(&chunk),
        "end_of_stream": end_of_stream
    });

    let Ok(output) = wasm_engine.execute(
        host,
        function,
        serde_json::to_vec(&payload).unwrap_or_default(),
    ) else {
        return chunk;
    };

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output) else {
        return chunk;
    };

    if value.get("action").and_then(|a| a.as_str()) == Some("Respond") {
        warn!(
            "{} returned Respond during streaming body hook; ignoring",
            function
        );
        return chunk;
    }

    value
        .get("body")
        .and_then(|b| b.as_str())
        .and_then(|b64| base64::prelude::BASE64_STANDARD.decode(b64).ok())
        .map(Bytes::from)
        .unwrap_or(chunk)
}

fn mutate_trailers(
    wasm_engine: &WasmEngine,
    host: &str,
    function: &'static str,
    mut trailers: hyper::HeaderMap,
) -> hyper::HeaderMap {
    if trailers.is_empty() {
        return trailers;
    }

    let payload = serde_json::json!({
        "trailers": trailers
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap_or("")))
            .collect::<std::collections::HashMap<_, _>>(),
        "end_of_stream": true
    });

    let Ok(output) = wasm_engine.execute(
        host,
        function,
        serde_json::to_vec(&payload).unwrap_or_default(),
    ) else {
        return trailers;
    };

    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output) else {
        return trailers;
    };

    apply_header_mutations(&mut trailers, &value);
    trailers
}

struct HookedBody<B> {
    inner: Pin<Box<B>>,
    wasm_engine: Arc<WasmEngine>,
    host: String,
    function: &'static str,
    trailers_function: &'static str,
    eos_emitted: bool,
    saw_trailers: bool,
}

fn single_chunk_body(
    bytes: Bytes,
    trailers: Option<hyper::HeaderMap>,
) -> BoxBody<Bytes, hyper::Error> {
    SingleChunkBody {
        data: Some(bytes),
        trailers,
    }
    .boxed()
}

struct SingleChunkBody {
    data: Option<Bytes>,
    trailers: Option<hyper::HeaderMap>,
}

impl hyper::body::Body for SingleChunkBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if let Some(data) = self.data.take() {
            return Poll::Ready(Some(Ok(hyper::body::Frame::data(data))));
        }

        if let Some(trailers) = self.trailers.take() {
            return Poll::Ready(Some(Ok(hyper::body::Frame::trailers(trailers))));
        }

        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        if let Some(data) = &self.data {
            hint.set_exact(data.len() as u64);
        } else {
            hint.set_exact(0);
        }
        hint
    }
}

impl<B> HookedBody<B> {
    fn new(
        inner: B,
        wasm_engine: Arc<WasmEngine>,
        host: String,
        function: &'static str,
        trailers_function: &'static str,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            wasm_engine,
            host,
            function,
            trailers_function,
            eos_emitted: false,
            saw_trailers: false,
        }
    }
}

impl<B> hyper::body::Body for HookedBody<B>
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error>,
{
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let end_of_stream = self.inner.as_ref().is_end_stream();
                    if end_of_stream {
                        self.eos_emitted = true;
                    }
                    let bytes = mutate_body_chunk_with_eos(
                        &self.wasm_engine,
                        &self.host,
                        self.function,
                        data,
                        end_of_stream,
                    );
                    Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))))
                }
                Err(frame) => match frame.into_trailers() {
                    Ok(trailers) => {
                        self.saw_trailers = true;
                        let trailers = mutate_trailers(
                            &self.wasm_engine,
                            &self.host,
                            self.trailers_function,
                            trailers,
                        );
                        Poll::Ready(Some(Ok(hyper::body::Frame::trailers(trailers))))
                    }
                    Err(frame) => Poll::Ready(Some(Ok(frame))),
                },
            },
            Poll::Ready(None) => {
                if !self.eos_emitted && !self.saw_trailers {
                    self.eos_emitted = true;
                    let eos = mutate_body_chunk_with_eos(
                        &self.wasm_engine,
                        &self.host,
                        self.function,
                        Bytes::new(),
                        true,
                    );
                    if !eos.is_empty() {
                        return Poll::Ready(Some(Ok(hyper::body::Frame::data(eos))));
                    }
                }
                Poll::Ready(None)
            }
            other => other,
        }
    }
}
