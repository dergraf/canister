//! TLS MITM tunnel: terminate the TLS handshake against a dynamically
//! generated server certificate, then dispatch the inner HTTP request
//! through the DLP-aware pipeline.

use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::debug;

use super::dlp_ctx::DlpCtx;
use super::limits::ProxyLimits;
use super::request::handle_inner_request;
use super::util::parse_host_from_authority;
use crate::ca::DynamicCa;
use crate::policy::OutboundPolicy;

pub(super) async fn handle_tunnel(
    upgraded: Upgraded,
    host_with_port: String,
    ca: Arc<DynamicCa>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
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
                handle_inner_request(
                    req,
                    dns_cache.clone(),
                    outbound_policy.clone(),
                    "https",
                    limits.clone(),
                    Some(dlp.clone()),
                )
            }),
        )
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(())
}
