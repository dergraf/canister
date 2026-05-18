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
    /// - `proxy-only` (default): outbound traffic must go through local proxy
    /// - `none`: no outbound networking
    /// - `direct`: direct outbound allowed, still policy-checked
    #[serde(default)]
    pub egress: Option<EgressMode>,

    /// Allowed domain names (resolved via internal DNS proxy).
    #[serde(default)]
    pub allow_domains: Vec<String>,

    /// Allowed IP addresses or CIDR ranges.
    #[serde(default)]
    pub allow_ips: Vec<String>,

    /// Port forwarding rules: map host ports to sandbox ports.
    ///
    /// Uses Docker/Podman syntax: `[ip:]hostPort:containerPort[/protocol]`.
    /// Supported when `egress != direct` (filtered networking).
    /// Forwarded ports are accessible from the host to the sandbox.
    #[serde(default)]
    pub ports: Vec<PortMapping>,

    /// Data Loss Prevention configuration for the egress proxy.
    #[serde(default)]
    pub dlp: Option<DlpConfig>,
}

impl NetworkConfig {
    /// Return the effective egress mode (defaults to proxy-only).
    pub fn egress(&self) -> EgressMode {
        self.egress.unwrap_or(EgressMode::ProxyOnly)
    }

    pub fn merge(self, overlay: Self) -> Self {
        Self {
            egress: overlay.egress.or(self.egress),
            allow_domains: union_vecs(self.allow_domains, overlay.allow_domains),
            allow_ips: union_vecs(self.allow_ips, overlay.allow_ips),
            ports: union_vecs(self.ports, overlay.ports),
            dlp: merge_dlp(self.dlp, overlay.dlp),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EgressMode {
    None,
    ProxyOnly,
    Direct,
}
