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
use super::secret_swap::SecretSwap;
use crate::ca::DynamicCa;
use crate::contracts::ContractTable;
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
    /// Per-destination egress contracts. Empty means "no FQDN egress
    /// permitted" — the contract gate refuses any host.
    pub hosts: Vec<can_policy::config::HostBlock>,
    /// In-netns address that pasta maps to host:127.0.0.1. Set by
    /// the sandbox after `setns()` when `network.allow_host_loopback`
    /// is `true`; used to resolve the `host.canister.local` alias.
    pub host_loopback_target: Option<std::net::IpAddr>,
    /// Fake→real env-var secret substitutions. The sandbox holds only the
    /// fakes; the proxy swaps in the real value on egress to an authorized
    /// host. Empty unless `[network.dlp] fake_secrets` is configured.
    pub secret_swaps: Vec<SecretSwap>,
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
            hosts: Vec::new(),
            host_loopback_target: None,
            secret_swaps: Vec::new(),
        }
    }

    pub fn with_network(mut self, network: can_policy::config::NetworkConfig) -> Self {
        self.network = Some(network);
        self
    }

    pub fn with_hosts(mut self, hosts: Vec<can_policy::config::HostBlock>) -> Self {
        self.hosts = hosts;
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

    pub fn with_host_loopback_target(mut self, target: std::net::IpAddr) -> Self {
        self.host_loopback_target = Some(target);
        self
    }

    pub fn with_secret_swaps(mut self, secret_swaps: Vec<SecretSwap>) -> Self {
        self.secret_swaps = secret_swaps;
        self
    }
}

pub struct ProxyServer {
    ca: Arc<DynamicCa>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    contracts: Arc<ContractTable>,
    limits: ProxyLimits,
    dlp: Option<DlpCtx>,
}

impl ProxyServer {
    pub fn new(config: ProxyServerConfig) -> Result<Self, ProxyError> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut outbound_policy = match &config.network {
            Some(network) => OutboundPolicy::from_config(network, &config.hosts),
            None => OutboundPolicy::default(),
        };
        outbound_policy.host_loopback_target = config.host_loopback_target;
        let limits = ProxyLimits::from_config(&config.proxy);
        let dlp = DlpCtx::from_config(&config)?;
        let contract_mode = config
            .network
            .as_ref()
            .map(|n| n.contract_mode())
            .unwrap_or_default();
        let contracts = Arc::new(ContractTable::new(config.hosts.clone(), contract_mode));

        Ok(Self {
            ca: config.ca,
            dns_cache: can_net::dns_cache::DnsCache::new(Duration::from_secs(15)),
            outbound_policy,
            contracts,
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
            let contracts = self.contracts.clone();
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
                                contracts.clone(),
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
