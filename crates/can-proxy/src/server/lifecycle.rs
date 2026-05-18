//! `ProxyServer` and its builder — the public lifecycle entry points.

use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tracing::{error, info};

use super::dlp_ctx::DlpCtx;
use super::limits::ProxyLimits;
use super::request::handle_proxy_request;
use crate::ca::DynamicCa;
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
    dlp: Option<DlpCtx>,
}

impl ProxyServer {
    pub fn new(config: ProxyServerConfig) -> Result<Self, ProxyError> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let outbound_policy = match &config.network {
            Some(network) => OutboundPolicy::from_config(network),
            None => OutboundPolicy::default(),
        };
        let limits = ProxyLimits::from_config(&config.proxy);
        let dlp = DlpCtx::from_config(&config)?;

        Ok(Self {
            ca: config.ca,
            dns_cache: can_net::dns_cache::DnsCache::new(Duration::from_secs(15)),
            outbound_policy,
            limits,
            dlp,
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
