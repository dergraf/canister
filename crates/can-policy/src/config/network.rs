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

    /// What the proxy does with a request for a host no `[[host]]` block
    /// declares (ADR-0018). `refuse` (default) turns it away at the
    /// connect gate; `sink` accepts it, runs it through the DLP and
    /// canary detectors, and answers it locally. Neither forwards
    /// anything upstream.
    #[serde(default)]
    pub undeclared_hosts: Option<UndeclaredHosts>,

    /// Route a workload that ignores `HTTP_PROXY` through the proxy anyway
    /// (ADR-0027): names resolve to the proxy, which serves ports 443 (by
    /// TLS SNI) and 80 (by `Host`) in the workload's network namespace.
    /// Rendered in the resolved policy only when on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparent: Option<bool>,

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
            undeclared_hosts: merge_undeclared_hosts(
                self.undeclared_hosts,
                overlay.undeclared_hosts,
            ),
            transparent: merge_transparent(self.transparent, overlay.transparent),
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

    /// Resolved handling of undeclared hosts (refuse if unset).
    pub fn undeclared_hosts(&self) -> UndeclaredHosts {
        self.undeclared_hosts.unwrap_or_default()
    }

    /// Whether egress is routed transparently (off unless set).
    pub fn transparent(&self) -> bool {
        self.transparent.unwrap_or(false)
    }
}

/// Handling of a request whose host no `[[host]]` block declares
/// (ADR-0018). Both modes keep the request from leaving the proxy; they
/// differ in how much of it the proxy looks at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UndeclaredHosts {
    /// Refuse at the connect gate: no TLS termination, no body read.
    #[default]
    Refuse,
    /// Terminate TLS with the sandbox CA, scan the request with the DLP
    /// and canary detectors, then answer it locally. Never forwarded.
    Sink,
}

/// Any layer turning transparent egress on wins: it changes nothing about
/// what may leave, only that a workload ignoring the proxy settings is
/// still seen.
fn merge_transparent(base: Option<bool>, overlay: Option<bool>) -> Option<bool> {
    match (base, overlay) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), _) | (_, Some(false)) => Some(false),
        (None, None) => None,
    }
}

/// An explicit `refuse` in any layer wins over `sink`: `refuse` is the
/// narrower proxy behaviour (no certificate minted, no hostile body
/// parsed for an arbitrary name), so a layer that pins it cannot be
/// silently widened by a later one. Otherwise any `sink` wins.
fn merge_undeclared_hosts(
    base: Option<UndeclaredHosts>,
    overlay: Option<UndeclaredHosts>,
) -> Option<UndeclaredHosts> {
    match (base, overlay) {
        (Some(UndeclaredHosts::Refuse), _) | (_, Some(UndeclaredHosts::Refuse)) => {
            Some(UndeclaredHosts::Refuse)
        }
        (Some(UndeclaredHosts::Sink), _) | (_, Some(UndeclaredHosts::Sink)) => {
            Some(UndeclaredHosts::Sink)
        }
        (None, None) => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn network(toml_src: &str) -> NetworkConfig {
        toml::from_str(toml_src).expect("network config parses")
    }

    #[test]
    fn undeclared_hosts_defaults_to_refuse() {
        let config = network("");
        assert_eq!(config.undeclared_hosts, None);
        assert_eq!(config.undeclared_hosts(), UndeclaredHosts::Refuse);
    }

    #[test]
    fn undeclared_hosts_parses_both_modes() {
        assert_eq!(
            network("undeclared_hosts = \"sink\"").undeclared_hosts(),
            UndeclaredHosts::Sink
        );
        assert_eq!(
            network("undeclared_hosts = \"refuse\"").undeclared_hosts(),
            UndeclaredHosts::Refuse
        );
    }

    #[test]
    fn undeclared_hosts_rejects_unknown_values() {
        assert!(toml::from_str::<NetworkConfig>("undeclared_hosts = \"forward\"").is_err());
        assert!(toml::from_str::<NetworkConfig>("undeclared_hosts = \"Sink\"").is_err());
        assert!(toml::from_str::<NetworkConfig>("undeclared_hosts = true").is_err());
    }

    #[test]
    fn undeclared_hosts_serializes_lowercase() {
        let config = NetworkConfig {
            undeclared_hosts: Some(UndeclaredHosts::Sink),
            ..Default::default()
        };
        let rendered = toml::to_string(&config).expect("serialize");
        assert!(
            rendered.contains("undeclared_hosts = \"sink\""),
            "{rendered}"
        );
    }

    #[test]
    fn undeclared_hosts_merge_table() {
        use UndeclaredHosts::{Refuse, Sink};
        let cases = [
            (None, None, None),
            (None, Some(Sink), Some(Sink)),
            (Some(Sink), None, Some(Sink)),
            (Some(Sink), Some(Sink), Some(Sink)),
            (None, Some(Refuse), Some(Refuse)),
            (Some(Refuse), None, Some(Refuse)),
            (Some(Refuse), Some(Sink), Some(Refuse)),
            (Some(Sink), Some(Refuse), Some(Refuse)),
            (Some(Refuse), Some(Refuse), Some(Refuse)),
        ];
        for (base, overlay, expected) in cases {
            let merged = NetworkConfig {
                undeclared_hosts: base,
                ..Default::default()
            }
            .merge(NetworkConfig {
                undeclared_hosts: overlay,
                ..Default::default()
            });
            assert_eq!(
                merged.undeclared_hosts, expected,
                "{base:?} merged with {overlay:?}"
            );
        }
    }

    #[test]
    fn bound_credentials_are_off_unless_a_layer_turns_them_on() {
        let bind = |src: &str| network(src).dlp.is_some_and(|d| d.bind_credentials());
        assert!(!bind(""));
        assert!(!bind("[dlp]\nenabled = true"));
        assert!(bind("[dlp]\nbind_credentials = true"));
        assert!(!bind("[dlp]\nbind_credentials = false"));

        let merged = |a: &str, b: &str| {
            network(a)
                .merge(network(b))
                .dlp
                .is_some_and(|d| d.bind_credentials())
        };
        assert!(merged(
            "[dlp]\nbind_credentials = true",
            "[dlp]\nbind_credentials = false"
        ));
        assert!(merged(
            "[dlp]\nbind_credentials = false",
            "[dlp]\nbind_credentials = true"
        ));
        assert!(merged("[dlp]\nbind_credentials = true", ""));
    }

    #[test]
    fn bound_credentials_are_rendered_only_when_set() {
        let off = toml::to_string(&network("[dlp]\nenabled = true")).expect("serialize");
        let on = toml::to_string(&network("[dlp]\nbind_credentials = true")).expect("serialize");
        assert!(!off.contains("bind_credentials"), "{off}");
        assert!(on.contains("bind_credentials = true"), "{on}");
    }

    #[test]
    fn transparent_egress_is_off_unless_a_layer_turns_it_on() {
        assert!(!network("").transparent());
        assert!(network("transparent = true").transparent());

        let merged = |a: Option<bool>, b: Option<bool>| {
            NetworkConfig {
                transparent: a,
                ..Default::default()
            }
            .merge(NetworkConfig {
                transparent: b,
                ..Default::default()
            })
            .transparent
        };
        assert_eq!(merged(None, None), None);
        assert_eq!(merged(Some(true), Some(false)), Some(true));
        assert_eq!(merged(Some(false), Some(true)), Some(true));
        assert_eq!(merged(Some(false), None), Some(false));
    }

    #[test]
    fn transparent_egress_is_rendered_only_when_on() {
        let off = toml::to_string(&network("")).expect("serialize");
        let on = toml::to_string(&network("transparent = true")).expect("serialize");

        assert!(!off.contains("transparent"), "{off}");
        assert!(on.contains("transparent = true"), "{on}");
    }
}
