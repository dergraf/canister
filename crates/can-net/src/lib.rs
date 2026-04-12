// can-net: Network isolation for the Canister sandbox.
//
// Provides:
// - Network namespace creation (CLONE_NEWNET)
// - Loopback interface setup
// - pasta integration for selective connectivity
// - DNS proxy with domain-based filtering
// - Port forwarding via pasta

pub mod dns;
pub mod netns;
pub mod pasta;

use std::net::IpAddr;

use can_policy::config::NetworkConfig;
use can_policy::whitelist;

/// Errors from network isolation operations.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("network namespace setup failed: {0}")]
    Namespace(nix::Error),

    #[error("loopback setup failed: {0}")]
    Loopback(std::io::Error),

    #[error("pasta failed: {0}")]
    Pasta(String),

    #[error("DNS proxy error: {0}")]
    Dns(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Describes what level of network access the sandbox should get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network at all — empty network namespace with only loopback.
    None,

    /// Filtered network — connectivity via pasta, DNS queries
    /// filtered through our proxy.
    Filtered,

    /// Full network — no CLONE_NEWNET (when deny_all is false and
    /// no specific allow rules are set). This is "trust mode".
    Full,
}

impl NetworkMode {
    /// Determine the appropriate network mode from policy config.
    ///
    /// Port forwarding requires Filtered mode, so its presence
    /// upgrades None → Filtered.
    pub fn from_config(config: &NetworkConfig) -> Self {
        if !config.deny_all() {
            return NetworkMode::Full;
        }

        let has_allowlist = !config.allow_domains.is_empty() || !config.allow_ips.is_empty();
        let has_ports = !config.ports.is_empty();

        if has_allowlist || has_ports {
            NetworkMode::Filtered
        } else {
            NetworkMode::None
        }
    }
}

/// State for the parent side of network isolation.
///
/// Holds handles to child processes (pasta) and the DNS proxy
/// thread so they can be cleaned up when the sandbox exits.
pub struct NetworkState {
    /// The pasta child process, if running.
    pub pasta_child: Option<std::process::Child>,

    /// Handle to the DNS proxy thread.
    pub dns_shutdown: Option<dns::DnsProxyHandle>,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkState {
    /// Create a new empty network state.
    pub fn new() -> Self {
        Self {
            pasta_child: None,
            dns_shutdown: None,
        }
    }

    /// Shut down all network infrastructure (pasta, DNS proxy).
    pub fn shutdown(&mut self) {
        if let Some(handle) = self.dns_shutdown.take() {
            handle.shutdown();
        }

        if let Some(mut child) = self.pasta_child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for NetworkState {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Check whether a resolved IP address is allowed by the network policy.
///
/// This is used by the DNS proxy to validate that resolved IPs are in
/// the whitelist (if IP-based filtering is enabled).
pub fn is_ip_allowed(ip: IpAddr, config: &NetworkConfig) -> bool {
    whitelist::check_ip(&ip.to_string(), config) == whitelist::AccessDecision::Allow
}

/// Check whether a domain is allowed by the network policy.
pub fn is_domain_allowed(domain: &str, config: &NetworkConfig) -> bool {
    whitelist::check_domain(domain, config) == whitelist::AccessDecision::Allow
}

/// Pre-resolve whitelisted domains to their IP addresses.
///
/// This is done in the parent process before sandboxing, so the results
/// can be used to build an IP allow-set for seccomp filtering.
///
/// Returns a map of domain -> resolved IPs.
pub fn resolve_allowed_domains(config: &NetworkConfig) -> Vec<(String, Vec<IpAddr>)> {
    use std::net::ToSocketAddrs;

    let mut results = Vec::new();

    for domain in &config.allow_domains {
        // Use the system resolver by trying to resolve domain:0.
        match (domain.as_str(), 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                if !ips.is_empty() {
                    tracing::debug!(domain, ips = ?ips, "resolved whitelisted domain");
                    results.push((domain.clone(), ips));
                } else {
                    tracing::warn!(domain, "whitelisted domain resolved to no addresses");
                }
            }
            Err(e) => {
                tracing::warn!(domain, error = %e, "failed to resolve whitelisted domain");
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_mode_deny_all_no_allowlist() {
        let config = NetworkConfig::default();
        assert_eq!(NetworkMode::from_config(&config), NetworkMode::None);
    }

    #[test]
    fn network_mode_deny_all_with_domains() {
        let config = NetworkConfig {
            allow_domains: vec!["example.com".to_string()],
            allow_ips: vec![],
            deny_all: Some(true),
            ports: vec![],
        };
        assert_eq!(NetworkMode::from_config(&config), NetworkMode::Filtered);
    }

    #[test]
    fn network_mode_deny_all_with_ips() {
        let config = NetworkConfig {
            allow_domains: vec![],
            allow_ips: vec!["10.0.0.0/8".to_string()],
            deny_all: Some(true),
            ports: vec![],
        };
        assert_eq!(NetworkMode::from_config(&config), NetworkMode::Filtered);
    }

    #[test]
    fn network_mode_allow_all() {
        let config = NetworkConfig {
            allow_domains: vec![],
            allow_ips: vec![],
            deny_all: Some(false),
            ports: vec![],
        };
        assert_eq!(NetworkMode::from_config(&config), NetworkMode::Full);
    }

    #[test]
    fn network_mode_ports_upgrade_to_filtered() {
        use can_policy::config::{PortMapping, PortProtocol};
        let config = NetworkConfig {
            allow_domains: vec![],
            allow_ips: vec![],
            deny_all: Some(true),
            ports: vec![PortMapping {
                host_ip: None,
                host_port: 8080,
                container_port: 80,
                protocol: PortProtocol::Tcp,
            }],
        };
        assert_eq!(NetworkMode::from_config(&config), NetworkMode::Filtered);
    }
}
