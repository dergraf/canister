use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::dlp::{DlpConfig, merge_dlp};
use super::filesystem::PortMapping;
use super::merge::union_vecs;

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Egress mode controls outbound networking behavior.
    ///
    /// - `proxy` (default): outbound traffic must go through the local proxy
    /// - `none`: no outbound networking
    ///
    /// The third runtime mode, `Direct` (unfiltered), is **not** settable
    /// here — it bypasses DLP and contract gates, so it is authored as
    /// `[unsafe] unfiltered_egress` and folded in at resolve time.
    #[serde(default)]
    pub egress: Option<EgressMode>,

    /// Global default for per-host contract enforcement when no
    /// matching `[[host]]` entry exists. `Strict` refuses unknown
    /// hosts; `Relaxed` allows them with a tracing event.
    /// Default: `Strict`.
    #[serde(default)]
    pub contract_mode: Option<super::host::ContractMode>,

    /// Allowed IP addresses / CIDRs (runtime-resolved). IP-literal egress
    /// carries no service identity and bypasses the per-host contract and
    /// DLP gates, so it is authored under `[unsafe] reachable_ips`.
    /// `#[serde(skip)]` makes `[network] allow_ips` a hard (unknown-field)
    /// error.
    #[serde(skip)]
    pub allow_ips: Vec<String>,

    /// Port forwarding rules (runtime-resolved). Authored under
    /// `[unsafe] expose_ports`; `#[serde(skip)]` rejects `[network] ports`.
    #[serde(skip)]
    pub ports: Vec<PortMapping>,

    /// Reach host loopback services via `host.canister.local`
    /// (runtime-resolved). Authored under `[unsafe] host_loopback`;
    /// `#[serde(skip)]` rejects `[network] allow_host_loopback`.
    #[serde(skip)]
    pub allow_host_loopback: bool,

    /// Data Loss Prevention configuration for the egress proxy.
    #[serde(default)]
    pub dlp: Option<DlpConfig>,
}

impl NetworkConfig {
    /// Return the effective egress mode (defaults to proxy).
    pub fn egress(&self) -> EgressMode {
        self.egress.unwrap_or(EgressMode::ProxyOnly)
    }

    pub fn merge(self, overlay: Self) -> Self {
        Self {
            egress: overlay.egress.or(self.egress),
            contract_mode: overlay.contract_mode.or(self.contract_mode),
            allow_ips: union_vecs(self.allow_ips, overlay.allow_ips),
            ports: union_vecs(self.ports, overlay.ports),
            allow_host_loopback: self.allow_host_loopback || overlay.allow_host_loopback,
            dlp: merge_dlp(self.dlp, overlay.dlp),
        }
    }

    /// Resolved global default contract mode (strict if unset).
    pub fn contract_mode(&self) -> super::host::ContractMode {
        self.contract_mode.unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EgressMode {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "proxy")]
    ProxyOnly,
    /// Unfiltered/direct egress. Not deserializable from `[network] egress`
    /// (recipes use `[unsafe] unfiltered_egress`); constructed at resolve
    /// time. Serializes as `direct` for diagnostics.
    #[serde(rename = "direct")]
    Direct,
}
