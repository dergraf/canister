//! Request handling: the top-level dispatcher (`handle_proxy_request`)
//! and the DLP-aware inner handler (`handle_inner_request`).
//!
//! `handle_inner_request` is composed of small named stages — gate by
//! policy, gate by DNS entropy, build upstream URI, scan headers/URI,
//! buffer-and-scan body, forward upstream, scan response. Each stage
//! returns either `Continue(...)` to feed the next stage or
//! `Refused(resp)` for an early exit. The dispatcher itself is just a
//! chain of `?`-style early exits.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Limited, combinators::BoxBody};
use hyper::{Method, Request, Response, StatusCode};
use tracing::{debug, error};

use can_dlp::entropy::dns_label_entropy;

use super::dlp_ctx::DlpCtx;
use super::dlp_enforce::enforce_request_verdicts;
use super::limits::ProxyLimits;
use super::passthrough::{handle_http_passthrough, handle_passthrough};
use super::response_scan::scan_response_for_canaries;
use super::responses::{ProxyBody, ProxyError, empty_body};
use super::stream_scan::stream_scan_body;
use super::tunnel::handle_tunnel;
use super::upstream::forward_upstream;
use super::util::{
    extract_host, host_allowed_by_outbound_policy, host_is_ip, parse_host_from_authority,
    update_content_length,
};
use crate::ca::DynamicCa;
use crate::egress;
use crate::policy::OutboundPolicy;

/// Top-level dispatch: CONNECT → tunnel-or-passthrough; WebSocket → 501;
/// everything else → inner handler.
pub(super) async fn handle_proxy_request(
    req: Request<hyper::body::Incoming>,
    ca: Arc<DynamicCa>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    limits: ProxyLimits,
    dlp: Option<DlpCtx>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    if req.method() == Method::CONNECT {
        return handle_connect(req, ca, dns_cache, outbound_policy, limits, dlp).await;
    }
    if crate::websocket::is_websocket_upgrade(&req) {
        return Ok(crate::websocket::not_implemented_ws_bridge().await);
    }
    match dlp {
        Some(ctx) => {
            handle_inner_request(req, dns_cache, outbound_policy, "http", limits, Some(ctx)).await
        }
        None => handle_http_passthrough(req, dns_cache, outbound_policy, limits).await,
    }
}

async fn handle_connect(
    req: Request<hyper::body::Incoming>,
    ca: Arc<DynamicCa>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    limits: ProxyLimits,
    dlp: Option<DlpCtx>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let authority = req
        .uri()
        .authority()
        .map(|a| a.to_string())
        .unwrap_or_default();
    let host_name_only = parse_host_from_authority(&authority);
    debug!("Received CONNECT request for {}", authority);

    // Refuse the CONNECT at the policy gate before we even establish the
    // TLS MITM. Without this, the proxy generates a fake server cert
    // and performs a TLS handshake for an arbitrary destination — leaking
    // SNI to the proxy, costing cert-generation work, and (pre-fix) then
    // happily forwarding the request upstream regardless of allow lists.
    if !host_allowed_by_outbound_policy(&host_name_only, &outbound_policy) {
        return Ok(
            ProxyError::policy_blocked(&host_name_only, host_is_ip(&host_name_only))
                .into_response(),
        );
    }

    let dlp_for_tunnel = dlp.clone();
    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Some(ctx) = dlp_for_tunnel {
                    if let Err(e) = handle_tunnel(
                        upgraded,
                        host_name_only,
                        ca,
                        dns_cache.clone(),
                        outbound_policy.clone(),
                        limits.clone(),
                        ctx,
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
    Ok(resp)
}

/// Inner-request handling, after TLS termination (or from plain HTTP
/// when DLP is enabled). Each stage is a named function below.
pub(super) async fn handle_inner_request(
    req: Request<hyper::body::Incoming>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    default_scheme: &'static str,
    limits: ProxyLimits,
    dlp: Option<DlpCtx>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    debug!("Intercepting request: {} {}", req.method(), req.uri());

    let host = extract_host(&req);

    // Stage 1: policy gate.
    if let Some(resp) = gate_by_policy(&host, &outbound_policy) {
        return Ok(resp);
    }

    // Stage 2: DNS-entropy gate (DLP only).
    if let Some(ctx) = dlp.as_ref() {
        if let Some(resp) = gate_by_dns_entropy(&host, ctx) {
            return Ok(resp);
        }
    }

    // Stage 3: upstream URI + headers.
    let (uri, original_scheme) = match egress::build_upstream_uri(
        &req,
        &host,
        default_scheme,
        limits.upstream_scheme.as_deref(),
    ) {
        Ok(v) => v,
        Err(err) => {
            error!("{}", err);
            return Ok(ProxyError::bad_request(&host).into_response());
        }
    };

    let (mut parts, body) = req.into_parts();
    // Drop the legacy header so it never reaches the upstream — the
    // proxy does not honour it (see egress.rs::build_upstream_uri).
    parts.headers.remove("x-canister-upstream-scheme");
    let original_uri = parts.uri.clone();
    parts.uri = uri;

    // Stage 4: scan headers + URI (DLP only).
    if let Some(ctx) = dlp.as_ref() {
        if let Some(resp) = scan_headers_and_uri(ctx, &parts, &original_uri, &host) {
            return Ok(resp);
        }
    }

    // Stage 5: buffer + scan body.
    let req_body =
        match buffer_and_scan_body(parts.headers.clone(), body, dlp.as_ref(), &limits, &host).await
        {
            BodyOutcome::Ready {
                body,
                content_length,
            } => {
                if let Some(len) = content_length {
                    update_content_length(&mut parts.headers, len);
                }
                body
            }
            BodyOutcome::Refused(resp) => return Ok(resp),
        };

    let mut upstream_req = Request::from_parts(parts, req_body);
    if original_scheme == "h2c" {
        egress::sanitize_h2c_headers(&mut upstream_req);
    }

    // Stage 6: forward + scan response.
    forward_and_scan_response(
        upstream_req,
        &dns_cache,
        &outbound_policy,
        &original_scheme,
        &limits,
        dlp.as_ref(),
        &host,
    )
    .await
}

fn gate_by_policy(host: &str, outbound_policy: &OutboundPolicy) -> Option<Response<ProxyBody>> {
    if host_allowed_by_outbound_policy(host, outbound_policy) {
        None
    } else {
        Some(ProxyError::policy_blocked(host, host_is_ip(host)).into_response())
    }
}

fn gate_by_dns_entropy(host: &str, ctx: &DlpCtx) -> Option<Response<ProxyBody>> {
    if !dns_label_entropy(host, ctx.dns_entropy_threshold) {
        return None;
    }
    tracing::warn!("DLP: high DNS label entropy for host {}", host);
    if ctx.monitor {
        None
    } else {
        Some(
            ProxyError::dlp_blocked(host, "dns-entropy")
                .no_event()
                .into_response(),
        )
    }
}

fn scan_headers_and_uri(
    ctx: &DlpCtx,
    parts: &hyper::http::request::Parts,
    original_uri: &hyper::Uri,
    host: &str,
) -> Option<Response<ProxyBody>> {
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let header_verdicts = ctx.scanner.scan_headers(&headers, host);
    if let Some(resp) = enforce_request_verdicts(&header_verdicts, host, ctx.monitor) {
        return Some(resp);
    }
    let uri_verdicts = ctx.scanner.scan_uri(&original_uri.to_string(), host);
    enforce_request_verdicts(&uri_verdicts, host, ctx.monitor)
}

enum BodyOutcome {
    Ready {
        body: BoxBody<Bytes, hyper::Error>,
        /// New content length (after re-buffering). `None` when the body
        /// was streamed through unchanged.
        content_length: Option<usize>,
    },
    Refused(Response<ProxyBody>),
}

async fn buffer_and_scan_body(
    headers: hyper::HeaderMap,
    body: hyper::body::Incoming,
    dlp: Option<&DlpCtx>,
    limits: &ProxyLimits,
    host: &str,
) -> BodyOutcome {
    let Some(ctx) = dlp else {
        return BodyOutcome::Ready {
            body: body.boxed(),
            content_length: None,
        };
    };

    let limited = Limited::new(body, limits.max_streamed_body_bytes);
    let collected = match limited.collect().await {
        Ok(c) => c,
        Err(_) => {
            return BodyOutcome::Refused(
                ProxyError::body_too_large(host, limits.max_streamed_body_bytes).into_response(),
            );
        }
    };
    let bytes = collected.to_bytes();
    let content_encoding = headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok());

    if bytes.len() <= limits.max_buffered_body_bytes {
        // Full pipeline: decode chain + decompression + unescape + regex.
        let body_verdicts = ctx.scanner.scan_body(&bytes, content_encoding, host);
        if let Some(resp) = enforce_request_verdicts(&body_verdicts, host, ctx.monitor) {
            return BodyOutcome::Refused(resp);
        }
        if ctx
            .scanner
            .check_entropy_budget(&bytes, host, &ctx.entropy_budget)
            .is_some()
            && !ctx.monitor
        {
            return BodyOutcome::Refused(
                ProxyError::dlp_blocked(host, "entropy-budget").into_response(),
            );
        }
    } else if let Some(resp) =
        stream_scan_body(&ctx.scanner, &bytes, host, &ctx.canaries, ctx.monitor)
    {
        return BodyOutcome::Refused(resp);
    }

    let len = bytes.len();
    BodyOutcome::Ready {
        body: super::responses::body_from(bytes),
        content_length: Some(len),
    }
}

async fn forward_and_scan_response(
    upstream_req: Request<BoxBody<Bytes, hyper::Error>>,
    dns_cache: &can_net::dns_cache::DnsCache,
    outbound_policy: &OutboundPolicy,
    original_scheme: &str,
    limits: &ProxyLimits,
    dlp: Option<&DlpCtx>,
    host: &str,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let upstream_fut = forward_upstream(dns_cache, outbound_policy, upstream_req, original_scheme);
    let response = match tokio::time::timeout(limits.upstream_request_timeout, upstream_fut).await {
        Ok(Ok(res)) => res,
        Ok(Err(e)) => {
            error!("upstream error: {}", e);
            return Ok(ProxyError::bad_gateway(host, e).into_response());
        }
        Err(_elapsed) => {
            return Ok(
                ProxyError::gateway_timeout(host, limits.upstream_request_timeout).into_response(),
            );
        }
    };

    // R8: scan response body for canary tokens. Cheap end of response-
    // direction DLP — fixed-set substring check, not the full regex
    // chain. Catches reflection / second-stage exfil where a malicious
    // upstream echoes the canary back.
    if let Some(ctx) = dlp {
        if !ctx.canaries.is_empty() {
            return Ok(scan_response_for_canaries(response, ctx, host, limits).await);
        }
    }
    Ok(response.map(|body| body.boxed()))
}
