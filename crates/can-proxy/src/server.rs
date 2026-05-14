use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, Limited, combinators::BoxBody};
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
use crate::wasm::{WasmEngine, WasmError};

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

/// Runtime limits shared with every request handler. Cloned freely; cheap.
#[derive(Clone, Debug)]
pub struct ProxyLimits {
    pub max_buffered_body_bytes: usize,
    pub wasm_hook_timeout: Duration,
    pub upstream_request_timeout: Duration,
    pub strict: bool,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_buffered_body_bytes:
                can_policy::config::ProxyConfig::DEFAULT_MAX_BUFFERED_BODY_BYTES,
            wasm_hook_timeout: Duration::from_millis(
                can_policy::config::ProxyConfig::DEFAULT_WASM_HOOK_TIMEOUT_MS,
            ),
            upstream_request_timeout: Duration::from_millis(
                can_policy::config::ProxyConfig::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_MS,
            ),
            strict: false,
        }
    }
}

impl ProxyLimits {
    pub fn from_config(proxy: &can_policy::config::ProxyConfig, strict: bool) -> Self {
        Self {
            max_buffered_body_bytes: proxy.max_buffered_body_bytes(),
            wasm_hook_timeout: proxy.wasm_hook_timeout(),
            upstream_request_timeout: proxy.upstream_request_timeout(),
            strict,
        }
    }
}

/// Single, fluent way to configure a `ProxyServer`. Replaces the three
/// previous `new*` constructors. Build with `ProxyServerConfig::new(ca)` and
/// chain `.with_interceptors`, `.with_network`, `.with_proxy_config`,
/// `.with_strict` as needed.
pub struct ProxyServerConfig {
    pub ca: Arc<DynamicCa>,
    pub interceptors: std::collections::HashMap<String, std::path::PathBuf>,
    pub network: Option<can_policy::config::NetworkConfig>,
    pub proxy: can_policy::config::ProxyConfig,
    pub strict: bool,
}

impl ProxyServerConfig {
    pub fn new(ca: Arc<DynamicCa>) -> Self {
        Self {
            ca,
            interceptors: Default::default(),
            network: None,
            proxy: Default::default(),
            strict: false,
        }
    }

    pub fn with_interceptors(
        mut self,
        interceptors: std::collections::HashMap<String, std::path::PathBuf>,
    ) -> Self {
        self.interceptors = interceptors;
        self
    }

    pub fn with_network(mut self, network: can_policy::config::NetworkConfig) -> Self {
        self.network = Some(network);
        self
    }

    pub fn with_proxy_config(mut self, proxy: can_policy::config::ProxyConfig) -> Self {
        self.proxy = proxy;
        self
    }

    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }
}

pub struct ProxyServer {
    ca: Arc<DynamicCa>,
    wasm_engine: Arc<WasmEngine>,
    client: HttpsClient,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    limits: ProxyLimits,
}

impl ProxyServer {
    pub fn new(config: ProxyServerConfig) -> Result<Self, ProxyError> {
        let wasm_engine = WasmEngine::new(&config.interceptors)?;
        let outbound_policy = match &config.network {
            Some(network) => OutboundPolicy::from_config(network),
            None => OutboundPolicy::default(),
        };

        // ProxyServer always uses interceptors from `ProxyServerConfig.interceptors`
        // (which is canonically `config.proxy.interceptors`). Build the limits
        // from the same `proxy` block so timeouts and body caps stay in sync.
        let limits = ProxyLimits::from_config(&config.proxy, config.strict);

        Ok(Self {
            ca: config.ca,
            wasm_engine: Arc::new(wasm_engine),
            client: build_client(),
            dns_cache: can_net::dns_cache::DnsCache::new(Duration::from_secs(15)),
            outbound_policy,
            limits,
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
            let limits = self.limits.clone();
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
                                limits.clone(),
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
    limits: ProxyLimits,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        let authority = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let host_name_only = parse_host_from_authority(&authority);
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
                            limits.clone(),
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
        return handle_inner_request(req, wasm_engine, client.clone(), "http", limits).await;
    }

    // Plain HTTP passthrough
    handle_http_passthrough(req, dns_cache, outbound_policy, limits).await
}

async fn handle_http_passthrough(
    req: Request<hyper::body::Incoming>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    limits: ProxyLimits,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let host = req
        .uri()
        .host()
        .map(|s| s.to_string())
        .unwrap_or_else(|| extract_host(&req));
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

            match tokio::time::timeout(limits.upstream_request_timeout, sender.send_request(req))
                .await
            {
                Ok(Ok(res)) => Ok(res.map(|body| body.boxed())),
                Ok(Err(e)) => Err(e),
                Err(_elapsed) => Ok(gateway_timeout_response(limits.upstream_request_timeout)),
            }
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
    limits: ProxyLimits,
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
            limits.wasm_hook_timeout,
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
                if let Some(resp) = handle_wasm_hook_error(&host, "on_request_headers", &e, &limits)
                {
                    return Ok(resp);
                }
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
        let limited = Limited::new(body, limits.max_buffered_body_bytes);
        let collected = match limited.collect().await {
            Ok(c) => c,
            Err(_) => {
                warn!(
                    "request body exceeded buffered limit of {} bytes for {}",
                    limits.max_buffered_body_bytes, host
                );
                return Ok(payload_too_large_response(limits.max_buffered_body_bytes));
            }
        };
        let trailers = collected.trailers().cloned().map(|trailers| {
            mutate_trailers(
                &wasm_engine,
                &host,
                "on_request_trailers",
                trailers,
                &limits,
            )
        });
        let has_trailers = trailers.as_ref().is_some_and(|t| !t.is_empty());
        let mut bytes = collected.to_bytes();
        bytes = mutate_body_chunk_with_eos(
            &wasm_engine,
            &host,
            "on_request_body",
            bytes,
            true,
            &limits,
        );

        update_length_headers(&mut parts.headers, bytes.len(), has_trailers);

        single_chunk_body(bytes, trailers)
    } else if has_plugin {
        HookedBody::new(
            body,
            wasm_engine.clone(),
            host.clone(),
            "on_request_body",
            "on_request_trailers",
            limits.clone(),
        )
        .boxed()
    } else {
        body.boxed()
    };
    let mut upstream_req = Request::from_parts(parts, req_body);
    if original_scheme == "h2c" {
        egress::sanitize_h2c_headers(&mut upstream_req);
    }

    let upstream_fut = egress::forward_request(client.clone(), upstream_req, &original_scheme);
    let upstream_result =
        match tokio::time::timeout(limits.upstream_request_timeout, upstream_fut).await {
            Ok(r) => r,
            Err(_elapsed) => {
                warn!(
                    "upstream request to {} exceeded timeout of {:?}",
                    host, limits.upstream_request_timeout
                );
                return Ok(gateway_timeout_response(limits.upstream_request_timeout));
            }
        };

    match upstream_result {
        Ok(mut res) => {
            let mut buffer_response_body = false;
            if has_plugin {
                let resp_headers_json = serde_json::json!({
                    "status": res.status().as_u16(),
                    "headers": res.headers().iter().map(|(k, v)| (k.as_str(), v.to_str().unwrap_or(""))).collect::<std::collections::HashMap<_, _>>()
                });

                match wasm_engine.execute(
                    &host,
                    "on_response_headers",
                    serde_json::to_vec(&resp_headers_json).unwrap_or_default(),
                    limits.wasm_hook_timeout,
                ) {
                    Ok(output) => {
                        if let Ok(resp_json) = serde_json::from_slice::<serde_json::Value>(&output)
                        {
                            if let Some(resp) = build_short_circuit_response(&resp_json) {
                                return Ok(resp);
                            }

                            apply_header_mutations(res.headers_mut(), &resp_json);
                            buffer_response_body = should_buffer_body(&resp_json);
                        }
                    }
                    Err(e) => {
                        if let Some(resp) =
                            handle_wasm_hook_error(&host, "on_response_headers", &e, &limits)
                        {
                            return Ok(resp);
                        }
                    }
                }
            }

            let (mut parts, body) = res.into_parts();
            let resp_body: BoxBody<Bytes, hyper::Error> = if has_plugin && buffer_response_body {
                let limited = Limited::new(body, limits.max_buffered_body_bytes);
                let collected = match limited.collect().await {
                    Ok(c) => c,
                    Err(_) => {
                        warn!(
                            "response body exceeded buffered limit of {} bytes for {}",
                            limits.max_buffered_body_bytes, host
                        );
                        return Ok(bad_gateway_oversized(limits.max_buffered_body_bytes));
                    }
                };
                let trailers = collected.trailers().cloned().map(|trailers| {
                    mutate_trailers(
                        &wasm_engine,
                        &host,
                        "on_response_trailers",
                        trailers,
                        &limits,
                    )
                });
                let has_trailers = trailers.as_ref().is_some_and(|t| !t.is_empty());
                let mut bytes = collected.to_bytes();
                bytes = mutate_body_chunk_with_eos(
                    &wasm_engine,
                    &host,
                    "on_response_body",
                    bytes,
                    true,
                    &limits,
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
                    limits.clone(),
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
    limits: ProxyLimits,
) -> Result<(), std::io::Error> {
    let host = parse_host_from_authority(&host_with_port);
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
                handle_inner_request(
                    req,
                    wasm_engine.clone(),
                    client.clone(),
                    "https",
                    limits.clone(),
                )
            }),
        )
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(())
}

fn split_target_host_port(target: &str) -> Result<(String, u16), std::io::Error> {
    // Handle bracketed IPv6: [::1]:8080 or [2001:db8::1]:443
    if let Some(stripped) = target.strip_prefix('[') {
        let close = stripped
            .find(']')
            .ok_or_else(|| std::io::Error::other("malformed IPv6 authority"))?;
        let host = &stripped[..close];
        let rest = &stripped[close + 1..];
        let port_str = rest
            .strip_prefix(':')
            .ok_or_else(|| std::io::Error::other("missing port after IPv6 authority"))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| std::io::Error::other("invalid port"))?;
        return Ok((host.to_string(), port));
    }

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

/// Parse the host out of an authority string. Correctly handles bracketed
/// IPv6 literals (`[::1]:8080` → `::1`) and bare host:port pairs alike. Falls
/// back to the input when the authority is malformed (rather than producing
/// silently corrupt output).
fn parse_host_from_authority(authority: &str) -> String {
    if let Some(stripped) = authority.strip_prefix('[') {
        if let Some(close) = stripped.find(']') {
            return stripped[..close].to_string();
        }
    }
    match authority.rsplit_once(':') {
        Some((host, _port)) if !host.is_empty() && !host.contains(':') => host.to_string(),
        _ => authority.to_string(),
    }
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

fn payload_too_large_response(limit: usize) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(full_body(format!(
        "Payload too large: buffered body exceeded {} bytes",
        limit
    )));
    *resp.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
    resp.headers_mut().insert(
        HeaderName::from_static("x-canister-error"),
        HeaderValue::from_static("body-too-large"),
    );
    resp
}

fn bad_gateway_oversized(limit: usize) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(full_body(format!(
        "Bad Gateway: upstream response exceeded buffered limit of {} bytes",
        limit
    )));
    *resp.status_mut() = StatusCode::BAD_GATEWAY;
    resp.headers_mut().insert(
        HeaderName::from_static("x-canister-error"),
        HeaderValue::from_static("upstream-body-too-large"),
    );
    resp
}

fn gateway_timeout_response(timeout: Duration) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(full_body(format!(
        "Gateway Timeout: upstream did not respond within {:?}",
        timeout
    )));
    *resp.status_mut() = StatusCode::GATEWAY_TIMEOUT;
    resp.headers_mut().insert(
        HeaderName::from_static("x-canister-error"),
        HeaderValue::from_static("upstream-timeout"),
    );
    resp
}

fn wasm_failure_response(
    host: &str,
    function: &str,
    err: &WasmError,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut resp = Response::new(full_body(format!(
        "Bad Gateway: wasm hook {} for {} failed: {}",
        function, host, err
    )));
    *resp.status_mut() = StatusCode::BAD_GATEWAY;
    resp.headers_mut().insert(
        HeaderName::from_static("x-canister-error"),
        match err {
            WasmError::Timeout { .. } => HeaderValue::from_static("wasm-timeout"),
            _ => HeaderValue::from_static("wasm-error"),
        },
    );
    resp
}

/// Centralised Wasm error handler. In strict mode, every hook failure short-
/// circuits with 502 (fail-closed). Otherwise headers-stage failures are
/// logged at warn! and the request proceeds without the filter's mutations
/// (preserves the pre-hardening behavior on streaming body hooks too).
///
/// Returns `Some(response)` when the caller should short-circuit with that
/// response; `None` when processing should continue without applying the
/// hook's output.
fn handle_wasm_hook_error(
    host: &str,
    function: &str,
    err: &WasmError,
    limits: &ProxyLimits,
) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
    match err {
        WasmError::Timeout { .. } => {
            warn!("wasm hook {} for {} timed out: {}", function, host, err);
        }
        _ => {
            warn!("wasm hook {} for {} failed: {}", function, host, err);
        }
    }

    if limits.strict {
        Some(wasm_failure_response(host, function, err))
    } else {
        None
    }
}

fn extract_host<B>(req: &Request<B>) -> String {
    if let Some(host) = req.uri().host() {
        return host.to_string();
    }
    req.headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .map(parse_host_from_authority)
        .unwrap_or_default()
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
                if header_value_is_safe(v_str) {
                    builder = builder.header(k, v_str);
                } else {
                    warn!(
                        "wasm short-circuit response header {} dropped: forbidden CR/LF/NUL",
                        k
                    );
                }
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

/// Reject any header value containing CR, LF, or NUL. Hyper would reject
/// these too via `HeaderValue::from_str`, but failing here gives a clear
/// log line naming the Wasm filter as the source rather than burying the
/// failure inside hyper.
fn header_value_is_safe(value: &str) -> bool {
    !value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

fn header_name_is_safe(name: &str) -> bool {
    // Header names must be tchar per RFC 7230. We rely on HeaderName::from_bytes
    // to fully validate, but explicitly reject the obvious smuggling chars
    // here so the warn! log is unambiguous about why the mutation was dropped.
    !name.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

fn apply_header_mutations(headers: &mut hyper::HeaderMap, hook_response: &serde_json::Value) {
    let Some(mutations) = hook_response.get("mutations") else {
        return;
    };

    if let Some(remove_headers) = mutations.get("remove_headers").and_then(|h| h.as_array()) {
        for name in remove_headers.iter().filter_map(|h| h.as_str()) {
            if !header_name_is_safe(name) {
                warn!("wasm remove_headers entry rejected (CR/LF/NUL): {:?}", name);
                continue;
            }
            if let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) {
                headers.remove(header_name);
            } else {
                warn!(
                    "wasm remove_headers entry rejected (not a valid header name): {:?}",
                    name
                );
            }
        }
    }

    if let Some(set_headers) = mutations.get("set_headers").and_then(|h| h.as_object()) {
        for (name, value) in set_headers {
            if !header_name_is_safe(name) {
                warn!("wasm set_headers name rejected (CR/LF/NUL): {:?}", name);
                continue;
            }
            let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
                warn!("wasm set_headers name rejected (invalid): {:?}", name);
                continue;
            };
            let Some(value) = value.as_str() else {
                continue;
            };
            if !header_value_is_safe(value) {
                warn!(
                    "wasm set_headers value for {} rejected (CR/LF/NUL)",
                    header_name
                );
                continue;
            }
            let Ok(header_value) = HeaderValue::from_str(value) else {
                warn!(
                    "wasm set_headers value for {} rejected (not a valid header value)",
                    header_name
                );
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
    limits: &ProxyLimits,
) -> Bytes {
    let payload = serde_json::json!({
        "body": base64::prelude::BASE64_STANDARD.encode(&chunk),
        "end_of_stream": end_of_stream
    });

    let output = match wasm_engine.execute(
        host,
        function,
        serde_json::to_vec(&payload).unwrap_or_default(),
        limits.wasm_hook_timeout,
    ) {
        Ok(o) => o,
        Err(e) => {
            // Streaming body hooks: log and pass the chunk through unchanged
            // rather than aborting the in-flight response mid-stream. Even in
            // strict mode this is the safer default — once headers are sent we
            // can no longer return a 502.
            warn!(
                "wasm streaming hook {} for {} failed: {}",
                function, host, e
            );
            return chunk;
        }
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
    limits: &ProxyLimits,
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

    let output = match wasm_engine.execute(
        host,
        function,
        serde_json::to_vec(&payload).unwrap_or_default(),
        limits.wasm_hook_timeout,
    ) {
        Ok(o) => o,
        Err(e) => {
            warn!("wasm trailers hook {} for {} failed: {}", function, host, e);
            return trailers;
        }
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
    limits: ProxyLimits,
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
        limits: ProxyLimits,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            wasm_engine,
            host,
            function,
            trailers_function,
            eos_emitted: false,
            saw_trailers: false,
            limits,
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
                        &self.limits,
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
                            &self.limits,
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
                        &self.limits,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_from_authority_ipv6_bracketed() {
        assert_eq!(parse_host_from_authority("[::1]:8080"), "::1");
        assert_eq!(
            parse_host_from_authority("[2001:db8::1]:443"),
            "2001:db8::1"
        );
    }

    #[test]
    fn parse_host_from_authority_ipv4_with_port() {
        assert_eq!(parse_host_from_authority("127.0.0.1:8080"), "127.0.0.1");
    }

    #[test]
    fn parse_host_from_authority_host_only() {
        assert_eq!(parse_host_from_authority("example.com"), "example.com");
    }

    #[test]
    fn parse_host_from_authority_bare_ipv6_falls_back() {
        // No brackets: ambiguous, but should not corrupt to "::1"
        assert_eq!(parse_host_from_authority("::1"), "::1");
    }

    #[test]
    fn header_value_safe_rejects_crlf() {
        assert!(header_value_is_safe("plain"));
        assert!(!header_value_is_safe("foo\r\nSet-Cookie: bad"));
        assert!(!header_value_is_safe("foo\nbar"));
        assert!(!header_value_is_safe("foo\0bar"));
    }

    #[test]
    fn split_target_host_port_ipv6() {
        assert_eq!(
            split_target_host_port("[::1]:8080").unwrap(),
            ("::1".to_string(), 8080)
        );
        assert_eq!(
            split_target_host_port("[2001:db8::1]:443").unwrap(),
            ("2001:db8::1".to_string(), 443)
        );
    }

    #[test]
    fn split_target_host_port_ipv4() {
        assert_eq!(
            split_target_host_port("example.com:80").unwrap(),
            ("example.com".to_string(), 80)
        );
    }
}
