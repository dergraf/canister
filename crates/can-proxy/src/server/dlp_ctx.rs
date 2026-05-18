//! DLP session state shared across requests in a proxy session.
//!
//! `DlpCtx::from_config` is the single place that decides whether DLP
//! is enabled and constructs all the dependent runtime state (scanner,
//! per-host budget, canary byte view). Callers get an `Option<DlpCtx>`
//! that's `Some` only when scanning will actually happen.

use std::sync::Arc;

use tracing::info;

use super::ProxyServerConfig;
use super::lifecycle::ProxyError;

/// Cloned into every request handler. Always cheap to clone (Arcs).
#[derive(Clone)]
pub(super) struct DlpCtx {
    pub(super) scanner: Arc<can_dlp::DlpScanner>,
    pub(super) entropy_budget: Arc<can_dlp::PerHostEntropyBudget>,
    pub(super) monitor: bool,
    pub(super) dns_entropy_threshold: f64,
    /// Raw canary byte sequences. The response-direction scanner uses
    /// these for a cheap substring check without re-running the regex.
    pub(super) canaries: Arc<Vec<Vec<u8>>>,
}

impl DlpCtx {
    /// Construct a `DlpCtx` from the proxy server config. Returns `None`
    /// when DLP scanning should be disabled — either explicitly via
    /// `dlp.enabled = false` or implicitly because `egress != proxy-only`.
    pub(super) fn from_config(config: &ProxyServerConfig) -> Result<Option<Self>, ProxyError> {
        let dlp_cfg = config.network.as_ref().and_then(|n| n.dlp.as_ref());

        let dlp_enabled = dlp_cfg.map(|d| d.is_enabled()).unwrap_or(false)
            || config
                .network
                .as_ref()
                .is_some_and(|n| n.egress() == can_policy::config::EgressMode::ProxyOnly);
        if !dlp_enabled {
            return Ok(None);
        }

        let user_scopes = dlp_cfg.map(|d| d.scopes.clone()).unwrap_or_default();
        let max_depth = dlp_cfg
            .map(|d| d.max_decode_depth())
            .unwrap_or(can_policy::config::DlpConfig::DEFAULT_MAX_DECODE_DEPTH);
        let do_decompress = dlp_cfg.map(|d| d.decompress()).unwrap_or(true);
        let budget_bytes = dlp_cfg
            .map(|d| d.session_entropy_budget())
            .unwrap_or(can_policy::config::DlpConfig::DEFAULT_SESSION_ENTROPY_BUDGET);
        let dns_threshold = dlp_cfg
            .map(|d| d.dns_entropy_threshold())
            .unwrap_or(can_policy::config::DlpConfig::DEFAULT_DNS_ENTROPY_THRESHOLD);

        let scanner = can_dlp::DlpScanner::new(
            config.canaries.clone(),
            &user_scopes,
            max_depth,
            do_decompress,
            config.strict,
        )
        .map_err(|e| ProxyError::Io(std::io::Error::other(format!("DLP init: {e}"))))?;

        info!(
            "DLP scanning enabled (strict={}, monitor={})",
            config.strict, config.monitor
        );

        let canary_bytes: Vec<Vec<u8>> = config
            .canaries
            .iter()
            .map(|c| c.as_bytes().to_vec())
            .collect();

        Ok(Some(Self {
            scanner: Arc::new(scanner),
            entropy_budget: Arc::new(can_dlp::PerHostEntropyBudget::new(budget_bytes)),
            monitor: config.monitor,
            dns_entropy_threshold: dns_threshold,
            canaries: Arc::new(canary_bytes),
        }))
    }
}
