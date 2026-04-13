// can-net: Network isolation for the Canister sandbox.
//
// Provides:
// - Network namespace creation (CLONE_NEWNET)
// - Loopback interface setup
// - pasta integration for selective connectivity
// - Port forwarding via pasta
//
// DNS filtering is handled by the seccomp notifier in can-sandbox,
// not by a separate DNS proxy. See notifier.rs for details.

pub mod netns;
pub mod pasta;

use std::net::IpAddr;

use can_policy::config::NetworkConfig;

/// Errors from network isolation operations.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("network namespace setup failed: {0}")]
    Namespace(nix::Error),

    #[error("loopback setup failed: {0}")]
    Loopback(std::io::Error),

    #[error("pasta failed: {0}")]
    Pasta(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Describes what level of network access the sandbox should get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network at all — empty network namespace with only loopback.
    None,

    /// Filtered network — connectivity via pasta, outbound connections
    /// and DNS queries filtered by the seccomp notifier.
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
/// Holds the pasta child process handle so it can be cleaned up when
/// the sandbox exits.
pub struct NetworkState {
    /// The pasta child process, if running.
    pub pasta_child: Option<std::process::Child>,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkState {
    /// Create a new empty network state.
    pub fn new() -> Self {
        Self { pasta_child: None }
    }

    /// Shut down all network infrastructure (pasta).
    pub fn shutdown(&mut self) {
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
