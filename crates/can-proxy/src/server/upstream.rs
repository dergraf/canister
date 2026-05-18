//! Upstream connection + forwarding. Decides scheme (http / https /
//! h2c), establishes the TCP/TLS connection through the DNS cache, and
//! ships the request to the destination.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tracing::error;

use crate::egress;
use crate::policy::OutboundPolicy;

pub(super) async fn forward_upstream(
    dns_cache: &can_net::dns_cache::DnsCache,
    outbound_policy: &OutboundPolicy,
    req: Request<BoxBody<Bytes, hyper::Error>>,
    original_scheme: &str,
) -> Result<Response<hyper::body::Incoming>, String> {
    if original_scheme == "h2c" {
        // h2c is feature-gated and intentionally not policy-checked here;
        // the upstream-scheme override path needs a follow-up to apply
        // `outbound_policy` before connecting. Tracked in the DLP plan.
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

    let stream = connect_via_cache(dns_cache, &host, port, outbound_policy)
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

/// Connect to `host:port`, honouring the outbound policy at every gate
/// (IP literals checked against `allow_ips`, DNS names checked against
/// `allow_domains`, resolved IPs checked against `allow_ips` again).
pub(super) async fn connect_via_cache(
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
