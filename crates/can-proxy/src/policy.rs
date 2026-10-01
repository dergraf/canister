use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Magic alias the sandbox can use to reach host loopback services
/// through the proxy. Resolved to the in-netns gateway IP (set via
/// `OutboundPolicy::host_loopback_target`) by pasta and the upstream
/// connector.
pub const HOST_LOOPBACK_ALIAS: &str = "host.canister.local";

#[derive(Clone)]
pub struct OutboundPolicy {
    pub allowed_domains: HashSet<String>,
    pub allowed_ips: HashSet<IpAddr>,
    pub allowed_cidrs: Vec<ipnet::IpNet>,
    pub enforce_ip_policy: bool,
    /// In-netns address that pasta maps to host:127.0.0.1. When set,
    /// the policy treats both [`HOST_LOOPBACK_ALIAS`] (as a host name)
    /// and this IP literal as allowed, and the upstream connector
    /// rewrites the dial target of alias requests to this IP.
    pub host_loopback_target: Option<IpAddr>,
    /// Hosts whose traffic is dialled to a port on the host's loopback
    /// instead of the real destination (`[[host]] upstream =
    /// "loopback:<port>"`, ADR-0013). Keyed by lower-cased domain.
    pub loopback_upstreams: HashMap<String, u16>,
    /// What happens to a request for a host no `[[host]]` block declares
    /// (ADR-0018). `ProxyServer::new` forces `Refuse` when DLP is off,
    /// because the sink exists to scan and has nothing to scan with.
    pub undeclared_hosts: can_policy::config::UndeclaredHosts,
}

impl Default for OutboundPolicy {
    fn default() -> Self {
        let mut allowed_ips = HashSet::new();
        allowed_ips.insert(
            "127.0.0.1"
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        );
        allowed_ips.insert(
            "::1"
                .parse()
                .unwrap_or(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        );

        Self {
            allowed_domains: HashSet::new(),
            allowed_ips,
            allowed_cidrs: Vec::new(),
            enforce_ip_policy: false,
            host_loopback_target: None,
            loopback_upstreams: HashMap::new(),
            undeclared_hosts: can_policy::config::UndeclaredHosts::Refuse,
        }
    }
}

impl OutboundPolicy {
    /// Build an outbound policy from network config + the resolved
    /// `[[host]]` blocks. The host blocks carry the FQDN allow-list:
    /// permission to dial an FQDN means "there's a `[[host]]` block
    /// for it."
    pub fn from_config(
        network: &can_policy::config::NetworkConfig,
        hosts: &[can_policy::config::HostBlock],
    ) -> Self {
        let mut policy = Self {
            allowed_domains: hosts
                .iter()
                .map(|h| h.domain.to_ascii_lowercase())
                .collect(),
            enforce_ip_policy: !network.allow_ips.is_empty(),
            undeclared_hosts: network.undeclared_hosts(),
            ..Self::default()
        };

        for host in hosts {
            // A malformed `upstream` is rejected at `ProxyServer::new`;
            // here an unparsable value simply routes nowhere special.
            if let Ok(Some(can_policy::config::UpstreamTarget::Loopback(port))) =
                host.upstream_target()
            {
                policy
                    .loopback_upstreams
                    .insert(host.domain.to_ascii_lowercase(), port);
            }
        }

        for item in &network.allow_ips {
            if let Ok(cidr) = item.parse::<ipnet::IpNet>() {
                policy.allowed_cidrs.push(cidr);
            } else if let Ok(ip) = item.parse::<IpAddr>() {
                policy.allowed_ips.insert(ip);
            }
        }

        policy
    }

    /// Whether undeclared hosts go to the sink instead of being refused.
    pub fn sinks_undeclared(&self) -> bool {
        self.undeclared_hosts == can_policy::config::UndeclaredHosts::Sink
    }

    /// The host-loopback port this host is routed to, if any.
    pub fn loopback_upstream(&self, host: &str) -> Option<u16> {
        if self.loopback_upstreams.is_empty() {
            return None;
        }
        self.loopback_upstreams
            .get(&host.to_ascii_lowercase())
            .copied()
    }

    pub fn allows_host(&self, host: &str) -> bool {
        if self.host_loopback_target.is_some() && host.eq_ignore_ascii_case(HOST_LOOPBACK_ALIAS) {
            return true;
        }
        if self.allowed_domains.is_empty() {
            return true;
        }

        // `*.X` admits subdomains of X only; a bare `X` admits X and its
        // subdomains — the reading `contracts.rs` `match_score` uses.
        let host = host.to_ascii_lowercase();
        self.allowed_domains
            .iter()
            .any(|domain| match domain.strip_prefix("*.") {
                Some(suffix) => host.ends_with(&format!(".{suffix}")),
                None => host == *domain || host.ends_with(&format!(".{domain}")),
            })
    }

    pub fn allows_ip_literal(&self, ip: IpAddr) -> bool {
        if Some(ip) == self.host_loopback_target {
            return true;
        }
        if !self.allowed_domains.is_empty() && !self.enforce_ip_policy {
            return false;
        }
        self.allows_ip(ip)
    }

    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        if Some(ip) == self.host_loopback_target {
            return true;
        }
        if !self.enforce_ip_policy {
            return true;
        }
        if self.allowed_ips.contains(&ip) {
            return true;
        }
        self.allowed_cidrs.iter().any(|cidr| cidr.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::{HOST_LOOPBACK_ALIAS, OutboundPolicy};
    use can_policy::config::HostBlock;
    use std::net::IpAddr;

    fn host(domain: &str) -> HostBlock {
        HostBlock {
            domain: domain.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn blocks_ip_literals_when_only_domains_are_configured() {
        let net = can_policy::config::NetworkConfig::default();
        let policy = OutboundPolicy::from_config(&net, &[host("hex.pm")]);
        assert!(!policy.allows_ip_literal("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn allows_subdomains_of_allowed_domain() {
        let net = can_policy::config::NetworkConfig::default();
        let policy = OutboundPolicy::from_config(&net, &[host("hex.pm")]);

        assert!(policy.allows_host("hex.pm"));
        assert!(policy.allows_host("repo.hex.pm"));
        assert!(!policy.allows_host("google.com"));
    }

    #[test]
    fn a_wildcard_block_allows_subdomains_but_not_the_apex() {
        // The contract gate already reads `*.X` this way (`contracts.rs`
        // `match_score`); the connect gate must agree, or a block accepted
        // at one stage is refused at the other.
        let net = can_policy::config::NetworkConfig::default();
        let policy = OutboundPolicy::from_config(&net, &[host("*.Example.org")]);

        assert!(policy.allows_host("a.example.org"));
        assert!(policy.allows_host("deep.a.example.org"));
        assert!(!policy.allows_host("example.org"));
        assert!(!policy.allows_host("notexample.org"));
        assert!(!policy.allows_host("example.org.evil.com"));
    }

    #[test]
    fn undeclared_hosts_are_refused_by_default() {
        let net = can_policy::config::NetworkConfig::default();
        let policy = OutboundPolicy::from_config(&net, &[host("hex.pm")]);

        assert!(!policy.sinks_undeclared());
        assert!(!OutboundPolicy::default().sinks_undeclared());
    }

    #[test]
    fn undeclared_hosts_sink_is_read_from_network_config() {
        let net = can_policy::config::NetworkConfig {
            undeclared_hosts: Some(can_policy::config::UndeclaredHosts::Sink),
            ..Default::default()
        };
        let policy = OutboundPolicy::from_config(&net, &[host("hex.pm")]);

        assert!(policy.sinks_undeclared());
        assert!(
            !policy.allows_host("google.com"),
            "the sink does not widen what may be dialled"
        );
    }

    #[test]
    fn host_loopback_alias_blocked_when_target_unset() {
        let net = can_policy::config::NetworkConfig::default();
        let policy = OutboundPolicy::from_config(&net, &[host("hex.pm")]);

        assert!(!policy.allows_host(HOST_LOOPBACK_ALIAS));
    }

    #[test]
    fn host_loopback_alias_allowed_when_target_set() {
        let net = can_policy::config::NetworkConfig::default();
        let mut policy = OutboundPolicy::from_config(&net, &[host("hex.pm")]);
        policy.host_loopback_target = Some("169.254.0.1".parse().unwrap());

        assert!(policy.allows_host(HOST_LOOPBACK_ALIAS));
        assert!(policy.allows_host("HOST.canister.local"));
        let target: IpAddr = "169.254.0.1".parse().unwrap();
        assert!(policy.allows_ip_literal(target));
        assert!(!policy.allows_host("google.com"));
    }
}
