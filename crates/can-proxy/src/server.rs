use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, Limited, combinators::BoxBody};
use hyper::header::{CONTENT_LENGTH, HOST, HeaderName, HeaderValue, TRANSFER_ENCODING};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tracing::{debug, error, info, warn};

use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use can_dlp::entropy::dns_label_entropy;

use crate::ca::DynamicCa;
use crate::egress;
use crate::policy::OutboundPolicy;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CA error: {0}")]
    Ca(#[from] crate::ca::CaError),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
}

#[derive(Clone, Debug)]
pub struct ProxyLimits {
    pub max_buffered_body_bytes: usize,
    pub upstream_request_timeout: Duration,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_buffered_body_bytes:
                can_policy::config::ProxyConfig::DEFAULT_MAX_BUFFERED_BODY_BYTES,
            upstream_request_timeout: Duration::from_millis(
                can_policy::config::ProxyConfig::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_MS,
            ),
        }
    }
}

impl ProxyLimits {
    pub fn from_config(proxy: &can_policy::config::ProxyConfig) -> Self {
        Self {
            max_buffered_body_bytes: proxy.max_buffered_body_bytes(),
            upstream_request_timeout: proxy.upstream_request_timeout(),
        }
    }
}

/// DLP scanning state shared across all requests in a proxy session.
#[derive(Clone)]
struct DlpCtx {
    scanner: Option<Arc<can_dlp::DlpScanner>>,
    entropy_budget: Option<Arc<can_dlp::SessionEntropyBudget>>,
    monitor: bool,
    dns_entropy_threshold: f64,
    allowed_domains: Arc<Vec<String>>,
}

impl DlpCtx {
    fn enabled(&self) -> bool {
        self.scanner.is_some()
    }
}

pub struct ProxyServerConfig {
    pub ca: Arc<DynamicCa>,
    pub network: Option<can_policy::config::NetworkConfig>,
    pub proxy: can_policy::config::ProxyConfig,
    pub strict: bool,
    pub monitor: bool,
    pub canaries: Vec<String>,
}

impl ProxyServerConfig {
    pub fn new(ca: Arc<DynamicCa>) -> Self {
        Self {
            ca,
            network: None,
            proxy: Default::default(),
            strict: false,
            monitor: false,
            canaries: Vec::new(),
        }
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

    pub fn with_monitor(mut self, monitor: bool) -> Self {
        self.monitor = monitor;
        self
    }

    pub fn with_canaries(mut self, canaries: Vec<String>) -> Self {
        self.canaries = canaries;
        self
    }
}

pub struct ProxyServer {
    ca: Arc<DynamicCa>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    limits: ProxyLimits,
    dlp: DlpCtx,
}

impl ProxyServer {
    pub fn new(config: ProxyServerConfig) -> Result<Self, ProxyError> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let outbound_policy = match &config.network {
            Some(network) => OutboundPolicy::from_config(network),
            None => OutboundPolicy::default(),
        };

        let limits = ProxyLimits::from_config(&config.proxy);

        let dlp_config = config.network.as_ref().and_then(|n| n.dlp.as_ref());

        let dlp_enabled = dlp_config.map(|d| d.is_enabled()).unwrap_or(false)
            || config
                .network
                .as_ref()
                .is_some_and(|n| n.egress() == can_policy::config::EgressMode::ProxyOnly);

        let (dlp_scanner, entropy_budget, dlp_dns_threshold) = if dlp_enabled {
            let extra_scopes = dlp_config
                .map(|d| d.extra_scopes.clone())
                .unwrap_or_default();
            let max_depth = dlp_config
                .map(|d| d.max_decode_depth())
                .unwrap_or(can_policy::config::DlpConfig::DEFAULT_MAX_DECODE_DEPTH);
            let do_decompress = dlp_config.map(|d| d.decompress()).unwrap_or(true);
            let budget_bytes = dlp_config
                .map(|d| d.session_entropy_budget())
                .unwrap_or(can_policy::config::DlpConfig::DEFAULT_SESSION_ENTROPY_BUDGET);
            let dns_threshold = dlp_config
                .map(|d| d.dns_entropy_threshold())
                .unwrap_or(can_policy::config::DlpConfig::DEFAULT_DNS_ENTROPY_THRESHOLD);

            let scanner = can_dlp::DlpScanner::new(
                config.canaries.clone(),
                &extra_scopes,
                max_depth,
                do_decompress,
                config.strict,
            )
            .map_err(|e| ProxyError::Io(std::io::Error::other(format!("DLP init: {e}"))))?;

            info!(
                "DLP scanning enabled (strict={}, monitor={})",
                config.strict, config.monitor
            );

            (
                Some(Arc::new(scanner)),
                Some(Arc::new(can_dlp::SessionEntropyBudget::new(budget_bytes))),
                dns_threshold,
            )
        } else {
            (
                None,
                None,
                can_policy::config::DlpConfig::DEFAULT_DNS_ENTROPY_THRESHOLD,
            )
        };

        let allowed_domains = Arc::new(
            config
                .network
                .as_ref()
                .map(|n| n.allow_domains.clone())
                .unwrap_or_default(),
        );

        Ok(Self {
            ca: config.ca,
            dns_cache: can_net::dns_cache::DnsCache::new(Duration::from_secs(15)),
            outbound_policy,
            limits,
            dlp: DlpCtx {
                scanner: dlp_scanner,
                entropy_budget,
                monitor: config.monitor,
                dns_entropy_threshold: dlp_dns_threshold,
                allowed_domains,
            },
        })
    }

    pub async fn run(&self, listener: tokio::net::TcpListener) -> Result<(), ProxyError> {
        info!("Proxy server listening on {}", listener.local_addr()?);

        loop {
            let (stream, _peer_addr) = listener.accept().await?;
            let io = TokioIo::new(stream);

            let ca = self.ca.clone();
            let dns_cache = self.dns_cache.clone();
            let outbound_policy = self.outbound_policy.clone();
            let limits = self.limits.clone();
            let dlp = self.dlp.clone();
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
                                dns_cache.clone(),
                                outbound_policy.clone(),
                                limits.clone(),
                                dlp.clone(),
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
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    limits: ProxyLimits,
    dlp: DlpCtx,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() == Method::CONNECT {
        let authority = req
            .uri()
            .authority()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let host_name_only = parse_host_from_authority(&authority);
        let dlp_enabled = dlp.enabled();
        debug!("Received CONNECT request for {}", authority);

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if dlp_enabled {
                        if let Err(e) = handle_tunnel(
                            upgraded,
                            host_name_only,
                            ca,
                            dns_cache.clone(),
                            limits.clone(),
                            dlp,
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

    if dlp.enabled() {
        return handle_inner_request(req, dns_cache, "http", limits, dlp).await;
    }

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
    req: Request<hyper::body::Incoming>,
    dns_cache: can_net::dns_cache::DnsCache,
    default_scheme: &'static str,
    limits: ProxyLimits,
    dlp: DlpCtx,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    debug!("Intercepting request: {} {}", req.method(), req.uri());

    let host = extract_host(&req);

    if dns_label_entropy(&host, dlp.dns_entropy_threshold) {
        warn!("DLP: high DNS label entropy for host {}", host);
        if !dlp.monitor {
            return Ok(dlp_blocked_response("dns-entropy", &host));
        }
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

    let (mut parts, body) = req.into_parts();
    parts.headers.remove("x-canister-upstream-scheme");
    let original_uri = parts.uri.clone();
    parts.uri = uri;

    if let Some(scanner) = &dlp.scanner {
        let allowed = &dlp.allowed_domains;
        let headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let header_verdicts = scanner.scan_headers(&headers, &host, allowed);
        if let Some(resp) = dlp_enforce(&header_verdicts, &host, dlp.monitor) {
            return Ok(resp);
        }

        let uri_verdicts = scanner.scan_uri(&original_uri.to_string(), &host, allowed);
        if let Some(resp) = dlp_enforce(&uri_verdicts, &host, dlp.monitor) {
            return Ok(resp);
        }
    }

    let req_body = if dlp.enabled() {
        let limited = Limited::new(body, limits.max_buffered_body_bytes);
        let collected = match limited.collect().await {
            Ok(c) => c,
            Err(_) => return Ok(payload_too_large_response(limits.max_buffered_body_bytes)),
        };
        let bytes = collected.to_bytes();

        if let Some(scanner) = &dlp.scanner {
            let content_encoding = parts
                .headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok());
            let body_verdicts =
                scanner.scan_body(&bytes, content_encoding, &host, &dlp.allowed_domains);
            if let Some(resp) = dlp_enforce(&body_verdicts, &host, dlp.monitor) {
                return Ok(resp);
            }

            if let Some(budget) = &dlp.entropy_budget {
                if scanner.check_entropy_budget(&bytes, budget).is_some() && !dlp.monitor {
                    return Ok(dlp_blocked_response("entropy-budget", &host));
                }
            }
        }

        update_content_length(&mut parts.headers, bytes.len());
        single_chunk_body(bytes)
    } else {
        body.boxed()
    };

    let mut upstream_req = Request::from_parts(parts, req_body);
    if original_scheme == "h2c" {
        egress::sanitize_h2c_headers(&mut upstream_req);
    }

    let upstream_fut = forward_upstream(&dns_cache, upstream_req, &original_scheme);
    match tokio::time::timeout(limits.upstream_request_timeout, upstream_fut).await {
        Ok(Ok(res)) => Ok(res.map(|body| body.boxed())),
        Ok(Err(e)) => {
            error!("upstream error: {}", e);
            let mut resp = Response::new(full_body(format!("Bad Gateway: {}", e)));
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(resp)
        }
        Err(_elapsed) => Ok(gateway_timeout_response(limits.upstream_request_timeout)),
    }
}

fn update_content_length(headers: &mut hyper::HeaderMap, len: usize) {
    if headers.contains_key(CONTENT_LENGTH) {
        headers.insert(CONTENT_LENGTH, HeaderValue::from(len));
    }
    headers.remove(TRANSFER_ENCODING);
}

fn build_upstream_tls_connector() -> Result<tokio_rustls::TlsConnector, std::io::Error> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = root_store.add(cert);
    }
    if root_store.is_empty() {
        return Err(std::io::Error::other(
            "no native TLS root certificates found",
        ));
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// Resolve DNS via DnsCache and connect TCP. Unlike `connect_via_cache`,
/// this skips outbound policy checks — the intercepted path trusts
/// DLP enablement as authorization.
async fn connect_upstream(
    dns_cache: &can_net::dns_cache::DnsCache,
    host: &str,
    port: u16,
) -> Result<tokio::net::TcpStream, std::io::Error> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return tokio::net::TcpStream::connect((ip, port)).await;
    }

    let cache = dns_cache.clone();
    let host_owned = host.to_string();
    let ips = tokio::task::spawn_blocking(move || cache.resolve_cached_or_lookup(&host_owned))
        .await
        .map_err(|e| std::io::Error::other(format!("dns lookup task failed: {e}")))?
        .ok_or_else(|| std::io::Error::other(format!("dns lookup failed for {host}")))?;

    let mut last_err: Option<std::io::Error> = None;
    for ip in ips {
        match tokio::net::TcpStream::connect((ip, port)).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| std::io::Error::other("all resolved IPs failed to connect")))
}

async fn forward_upstream(
    dns_cache: &can_net::dns_cache::DnsCache,
    req: Request<BoxBody<Bytes, hyper::Error>>,
    original_scheme: &str,
) -> Result<Response<hyper::body::Incoming>, String> {
    if original_scheme == "h2c" {
        return egress::forward_h2c_request(req).await;
    }

    let host = req
        .uri()
        .host()
        .ok_or("missing host in upstream URI")?
        .to_string();
    let port = req
        .uri()
        .port_u16()
        .unwrap_or(if original_scheme == "https" { 443 } else { 80 });

    let stream = connect_upstream(dns_cache, &host, port)
        .await
        .map_err(|e| format!("upstream connect to {host}:{port} failed: {e}"))?;

    if original_scheme == "https" {
        let connector =
            build_upstream_tls_connector().map_err(|e| format!("TLS connector: {e}"))?;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| format!("invalid server name '{host}': {e}"))?;
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("upstream TLS handshake with {host}: {e}"))?;
        let io = TokioIo::new(tls_stream);

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await
            .map_err(|e| format!("HTTP handshake with {host}: {e}"))?;

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                error!("upstream TLS connection error: {:?}", err);
            }
        });

        sender.send_request(req).await.map_err(|e| e.to_string())
    } else {
        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await
            .map_err(|e| format!("HTTP handshake with {host}: {e}"))?;

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                error!("upstream connection error: {:?}", err);
            }
        });

        sender.send_request(req).await.map_err(|e| e.to_string())
    }
}

async fn handle_tunnel(
    upgraded: Upgraded,
    host_with_port: String,
    ca: Arc<DynamicCa>,
    dns_cache: can_net::dns_cache::DnsCache,
    limits: ProxyLimits,
    dlp: DlpCtx,
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
                handle_inner_request(req, dns_cache.clone(), "https", limits.clone(), dlp.clone())
            }),
        )
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(())
}

fn split_target_host_port(target: &str) -> Result<(String, u16), std::io::Error> {
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

fn single_chunk_body(bytes: Bytes) -> BoxBody<Bytes, hyper::Error> {
    Full::new(bytes).map_err(|never| match never {}).boxed()
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

fn dlp_blocked_response(detector: &str, host: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    warn!("DLP blocked request to {}: detector={}", host, detector);
    let mut resp = Response::new(full_body(format!(
        "Unavailable For Legal Reasons: DLP policy violation ({})",
        detector
    )));
    *resp.status_mut() = StatusCode::from_u16(451).unwrap_or(StatusCode::FORBIDDEN);
    resp.headers_mut().insert(
        HeaderName::from_static("x-canister-error"),
        HeaderValue::from_static("dlp-blocked"),
    );
    if let Ok(val) = HeaderValue::from_str(detector) {
        resp.headers_mut()
            .insert(HeaderName::from_static("x-canister-dlp-detector"), val);
    }
    resp
}

fn dlp_enforce(
    verdicts: &[can_dlp::ScanVerdict],
    host: &str,
    monitor: bool,
) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
    for v in verdicts {
        let detector_name = format!("{:?}", v.detector);
        match v.action {
            can_dlp::DetectorAction::Block => {
                if monitor {
                    warn!(
                        "DLP finding (monitor): detector={}, host={}, matched={}",
                        detector_name, host, v.matched_text
                    );
                } else {
                    return Some(dlp_blocked_response(&detector_name, host));
                }
            }
            can_dlp::DetectorAction::Warn => {
                warn!(
                    "DLP warning: detector={}, host={}, matched={}",
                    detector_name, host, v.matched_text
                );
            }
        }
    }
    None
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
        assert_eq!(parse_host_from_authority("::1"), "::1");
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
