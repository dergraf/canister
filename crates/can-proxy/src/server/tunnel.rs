//! TLS MITM tunnel: terminate the TLS handshake against a dynamically
//! generated server certificate, then dispatch the inner HTTP request
//! through the DLP-aware pipeline.

use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use super::capture::CaptureCtx;
use super::dlp_ctx::DlpCtx;
use super::limits::ProxyLimits;
use super::request::handle_inner_request;
use super::util::parse_host_from_authority;
use crate::ca::DynamicCa;
use crate::policy::OutboundPolicy;

// 10 distinct args, all genuinely required: TLS materials, dial state,
// gates, dlp ctx, capture ctx, sink pin. Bundling into one struct just shifts the
// noise.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_tunnel<T>(
    io: T,
    host_with_port: String,
    ca: Arc<DynamicCa>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    contracts: Arc<crate::contracts::ContractTable>,
    limits: ProxyLimits,
    dlp: DlpCtx,
    capture: Option<CaptureCtx>,
    tunnel_sunk: bool,
) -> Result<(), std::io::Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = parse_host_from_authority(&host_with_port);
    debug!("Establishing TLS tunnel for {}", host);

    let tls_acceptor = TlsAcceptor::from(server_config(&ca, &host)?);
    let tls_stream = tls_acceptor.accept(io).await?;

    serve_tls(
        tls_stream,
        dns_cache,
        outbound_policy,
        contracts,
        limits,
        dlp,
        capture,
        tunnel_sunk,
    )
    .await
}

/// A TLS server configuration presenting a certificate for `host`, signed
/// by the sandbox CA.
pub(super) fn server_config(
    ca: &DynamicCa,
    host: &str,
) -> Result<Arc<ServerConfig>, std::io::Error> {
    let (cert, key) = ca
        .generate_server_cert(host)
        .map_err(|e| std::io::Error::other(format!("Failed to generate cert: {}", e)))?;

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map(Arc::new)
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Serve the HTTP requests on an established TLS connection through the
/// DLP-aware pipeline.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_tls<T>(
    tls_stream: tokio_rustls::server::TlsStream<T>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    contracts: Arc<crate::contracts::ContractTable>,
    limits: ProxyLimits,
    dlp: DlpCtx,
    capture: Option<CaptureCtx>,
    tunnel_sunk: bool,
) -> Result<(), std::io::Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    http1::Builder::new()
        .serve_connection(
            TokioIo::new(tls_stream),
            service_fn(move |req| {
                handle_inner_request(
                    req,
                    dns_cache.clone(),
                    outbound_policy.clone(),
                    contracts.clone(),
                    "https",
                    limits.clone(),
                    Some(dlp.clone()),
                    capture.clone(),
                    tunnel_sunk,
                )
            }),
        )
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
}
