//! Passthrough paths: non-MITM forwarding for both plain HTTP and the
//! TCP-over-CONNECT tunnel that runs when DLP is disabled.

use http_body_util::BodyExt;
use hyper::upgrade::Upgraded;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tracing::{debug, error};

use super::limits::ProxyLimits;
use super::responses::{ProxyBody, ProxyError};
use super::upstream::connect_via_cache;
use super::util::extract_host;
use crate::policy::OutboundPolicy;

/// Plain-HTTP forwarding (no DLP). Used when DLP is disabled and the
/// inbound request is `http://...` (no TLS termination needed).
pub(super) async fn handle_http_passthrough(
    req: Request<hyper::body::Incoming>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    limits: ProxyLimits,
) -> Result<Response<ProxyBody>, hyper::Error> {
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
                Err(_elapsed) => Ok(ProxyError::gateway_timeout(
                    &host,
                    limits.upstream_request_timeout,
                )
                .into_response()),
            }
        }
        Err(e) => Ok(ProxyError::bad_gateway(&host, e.to_string()).into_response()),
    }
}

/// TCP passthrough over a CONNECT-upgraded stream. Used when DLP is
/// disabled and the inbound is `CONNECT host:port`. We don't terminate
/// TLS — just bidirectional copy bytes.
pub(super) async fn handle_passthrough(
    upgraded: Upgraded,
    target: String,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
) -> Result<(), std::io::Error> {
    debug!("Establishing TCP passthrough for {}", target);
    let (host, port) = super::util::split_target_host_port(&target)?;
    let mut server = connect_via_cache(&dns_cache, &host, port, &outbound_policy).await?;
    let mut client = TokioIo::new(upgraded);
    tokio::io::copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
}
