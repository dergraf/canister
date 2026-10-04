//! Transparent egress (ADR-0027): the proxy also serves ports 443 and 80
//! in the workload's network namespace, where every name resolves to it
//! (`crate::dns_stub`). A client that ignores `HTTP_PROXY` connects there,
//! and the request takes the same path a proxied one does: the connect
//! gate, the undeclared-host sink, TLS termination, DLP, capture, events.

use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::LazyConfigAcceptor;
use tracing::debug;

use super::capture::CaptureCtx;
use super::dlp_ctx::DlpCtx;
use super::limits::ProxyLimits;
use super::request::{TunnelGate, handle_proxy_request, tunnel_gate};
use super::tunnel::{serve_tls, server_config};
use crate::ca::DynamicCa;
use crate::policy::OutboundPolicy;

/// `egress_request.reason` for a transparent TLS connection whose client
/// aborted the handshake, typically because it does not trust the sandbox
/// CA (it read neither `SSL_CERT_FILE` nor the proxy settings).
pub const CLIENT_REJECTED_CA: &str = "client_rejected_ca";

/// The sockets transparent egress serves, bound in the workload's network
/// namespace: TLS on 443, plain HTTP on 80, the stub resolver on 53.
pub struct TransparentListeners {
    pub tls: TcpListener,
    pub http: TcpListener,
    pub dns: UdpSocket,
}

/// What a connection handler needs from the server, cloned per connection.
#[derive(Clone)]
pub(super) struct Shared {
    pub(super) ca: Arc<DynamicCa>,
    pub(super) dns_cache: can_net::dns_cache::DnsCache,
    pub(super) outbound_policy: OutboundPolicy,
    pub(super) contracts: Arc<crate::contracts::ContractTable>,
    pub(super) limits: ProxyLimits,
    pub(super) dlp: Option<DlpCtx>,
    pub(super) capture: Option<CaptureCtx>,
}

/// Serve all three listeners until they fail.
pub(super) fn spawn(listeners: TransparentListeners, shared: Shared) {
    tokio::task::spawn(crate::dns_stub::serve(listeners.dns));

    let tls_shared = shared.clone();
    tokio::task::spawn(async move {
        while let Ok((tcp, _peer)) = listeners.tls.accept().await {
            tokio::task::spawn(tls_connection(tcp, tls_shared.clone()));
        }
    });

    tokio::task::spawn(async move {
        while let Ok((tcp, _peer)) = listeners.http.accept().await {
            tokio::task::spawn(http_connection(tcp, shared.clone()));
        }
    });
}

/// A TLS connection made directly to the proxy: the host comes from SNI,
/// read before any certificate is chosen.
async fn tls_connection(tcp: TcpStream, shared: Shared) {
    let start = match LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp).await {
        Ok(start) => start,
        Err(e) => {
            debug!("transparent TLS: no ClientHello: {e}");
            return;
        }
    };

    let Some(host) = start.client_hello().server_name().map(str::to_string) else {
        crate::events::egress_blocked("", "CONNECT", "", "no_sni");
        return;
    };

    let Some(dlp) = shared.dlp.clone() else {
        crate::events::egress_blocked(&host, "CONNECT", "", "policy");
        return;
    };

    let tunnel_sunk = match tunnel_gate(&host, &shared.outbound_policy, &shared.contracts, true) {
        TunnelGate::Open => false,
        TunnelGate::Sunk => true,
        TunnelGate::Refused => return,
    };

    let result = async {
        let config = server_config(&shared.ca, &host)?;
        // A client reaching the proxy without its proxy settings may well
        // lack the CA they would have brought (`SSL_CERT_FILE`) and abort
        // the handshake. The attempt is then recorded, not lost.
        let tls = match start.into_stream(config).await {
            Ok(tls) => tls,
            Err(e) => {
                crate::events::egress_blocked(&host, "CONNECT", "", CLIENT_REJECTED_CA);
                return Err(e);
            }
        };
        serve_tls(
            tls,
            shared.dns_cache,
            shared.outbound_policy,
            shared.contracts,
            shared.limits,
            dlp,
            shared.capture,
            tunnel_sunk,
        )
        .await
    }
    .await;

    if let Err(e) = result {
        debug!("transparent TLS for {host}: {e}");
    }
}

/// A plain HTTP connection made directly to the proxy: the host comes from
/// each request's `Host` header.
async fn http_connection(tcp: TcpStream, shared: Shared) {
    let result = http1::Builder::new()
        .serve_connection(
            TokioIo::new(tcp),
            service_fn(move |req| {
                handle_proxy_request(
                    req,
                    shared.ca.clone(),
                    shared.dns_cache.clone(),
                    shared.outbound_policy.clone(),
                    shared.contracts.clone(),
                    shared.limits.clone(),
                    shared.dlp.clone(),
                    shared.capture.clone(),
                )
            }),
        )
        .await;

    if let Err(e) = result {
        debug!("transparent HTTP: {e}");
    }
}
