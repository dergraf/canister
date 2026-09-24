//! `ProxyServer` and its builder — the public lifecycle entry points.

use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tracing::{error, info};

use super::capture::CaptureCtx;
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
    #[error("proxy configuration error: {0}")]
    Config(String),
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
    /// Externally supplied, tagged canaries (ADR-0012). Recognized on
    /// egress like generated canaries, but classified by data class and
    /// allowed at the destinations their class permits.
    pub external_canaries: Vec<can_policy::config::ExternalCanary>,
    /// How often the proxy emits a cumulative `stats` event (ADR-0015).
    /// `None` disables periodic stats; a final snapshot is still emitted
    /// on shutdown when an event stream is installed.
    pub stats_interval_ms: Option<u64>,
    /// Exchange capture settings (ADR-0011). `None` (the default) records
    /// nothing. Capture requires the DLP pipeline, which `egress =
    /// proxy-only` turns on.
    pub capture: Option<can_events::CaptureConfig>,
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
            external_canaries: Vec::new(),
            stats_interval_ms: None,
            capture: None,
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

    pub fn with_external_canaries(
        mut self,
        external_canaries: Vec<can_policy::config::ExternalCanary>,
    ) -> Self {
        self.external_canaries = external_canaries;
        self
    }

    pub fn with_stats_interval_ms(mut self, interval_ms: Option<u64>) -> Self {
        self.stats_interval_ms = interval_ms;
        self
    }

    pub fn with_capture(mut self, capture: can_events::CaptureConfig) -> Self {
        self.capture = Some(capture);
        self
    }
}

/// Reject a mock route that could never be dialled, or that would not be
/// mediated, at construction time: a per-request failure here would look
/// like an upstream outage and quietly send nothing where the operator
/// expected a local mock (ADR-0013).
fn validate_upstreams(config: &ProxyServerConfig) -> Result<(), ProxyError> {
    let egress = config
        .network
        .as_ref()
        .map(|network| network.egress())
        .unwrap_or(can_policy::config::EgressMode::ProxyOnly);

    for host in &config.hosts {
        let target = host
            .upstream_target()
            .map_err(|err| ProxyError::Config(err.to_string()))?;
        if target.is_none() {
            continue;
        }
        if config.host_loopback_target.is_none() {
            return Err(ProxyError::Config(format!(
                "[[host]] {} sets upstream = {:?}, which requires [unsafe] host_loopback = true",
                host.domain,
                host.upstream.as_deref().unwrap_or_default()
            )));
        }
        // Routing only keeps its ADR-0013 promise — TLS terminated, the
        // contract applied, DLP scanned — on the mediated path. Under any
        // other egress mode a CONNECT is passed through untouched, and a
        // route would hand the workload an unmediated pipe to a
        // host-local service instead of a mock.
        if egress != can_policy::config::EgressMode::ProxyOnly {
            return Err(ProxyError::Config(format!(
                "[[host]] {} sets upstream = {:?}, which requires [network] egress = \"proxy\"; \
                 under {:?} egress a routed host would not be mediated",
                host.domain,
                host.upstream.as_deref().unwrap_or_default(),
                egress
            )));
        }
    }
    Ok(())
}

pub struct ProxyServer {
    ca: Arc<DynamicCa>,
    dns_cache: can_net::dns_cache::DnsCache,
    outbound_policy: OutboundPolicy,
    contracts: Arc<ContractTable>,
    limits: ProxyLimits,
    dlp: Option<DlpCtx>,
    capture: Option<CaptureCtx>,
    stats_interval: Option<Duration>,
}

impl ProxyServer {
    /// Emit a cumulative `stats` snapshot on a fixed interval. The first
    /// tick fires immediately in tokio, so it is consumed up front to
    /// keep the first real snapshot one interval in.
    fn spawn_stats_ticker(&self) {
        let Some(interval) = self.stats_interval else {
            return;
        };

        tokio::task::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                super::stats::emit_snapshot();
            }
        });
    }

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
        validate_upstreams(&config)?;
        let contracts = Arc::new(ContractTable::new(config.hosts.clone(), contract_mode));
        if !config.external_canaries.is_empty() && dlp.is_none() {
            tracing::warn!(
                "external canaries are configured but DLP is off; they will not be watched for \
                 (set `egress = \"proxy-only\"` or `[network.dlp] enabled = true`)"
            );
        }

        let capture = CaptureCtx::from_config(&config);
        if capture.is_some() && dlp.is_none() {
            tracing::warn!(
                "exchange capture is enabled but DLP is off; nothing will be captured \
                 (capture runs in the DLP pipeline — set `egress = \"proxy-only\"`)"
            );
        }

        Ok(Self {
            ca: config.ca,
            dns_cache: can_net::dns_cache::DnsCache::new(Duration::from_secs(15)),
            outbound_policy,
            contracts,
            limits,
            dlp,
            capture,
            stats_interval: config
                .stats_interval_ms
                .filter(|ms| *ms > 0)
                .map(Duration::from_millis),
        })
    }

    pub async fn run(&self, listener: tokio::net::TcpListener) -> Result<(), ProxyError> {
        info!("Proxy server listening on {}", listener.local_addr()?);

        self.spawn_stats_ticker();

        // The sandbox tears the proxy down when the workload exits. Catch
        // the terminate signal so the last `stats` snapshot (ADR-0015)
        // still makes it into the stream; the sandbox follows up with
        // SIGKILL if we take too long.
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(ProxyError::Io)?;

        loop {
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                _ = terminate.recv() => {
                    super::stats::emit_snapshot();
                    // Seal before the sandbox's SIGKILL arrives: an
                    // unsealed proxy stream is reported as unsealed, and
                    // "the proxy was killed" should not read as
                    // "the evidence was tampered with" (ADR-0016).
                    can_events::seal();
                    info!("Proxy server shutting down");
                    return Ok(());
                }
            };
            let (stream, _peer_addr) = accepted?;
            let io = TokioIo::new(stream);

            let ca = self.ca.clone();
            let dns_cache = self.dns_cache.clone();
            let outbound_policy = self.outbound_policy.clone();
            let contracts = self.contracts.clone();
            let limits = self.limits.clone();
            let dlp = self.dlp.clone();
            let capture = self.capture.clone();
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
                                capture.clone(),
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
