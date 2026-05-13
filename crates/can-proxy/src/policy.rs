use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Clone)]
pub struct OutboundPolicy {
    pub allowed_domains: HashSet<String>,
    pub allowed_ips: HashSet<IpAddr>,
    pub allowed_cidrs: Vec<ipnet::IpNet>,
    pub enforce_ip_policy: bool,
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
        }
    }
}

impl OutboundPolicy {
    pub fn from_config(network: &can_policy::config::NetworkConfig) -> Self {
        let mut policy = Self {
            allowed_domains: network
                .allow_domains
                .iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
            enforce_ip_policy: !network.allow_ips.is_empty(),
            ..Self::default()
        };

        for item in &network.allow_ips {
            if let Ok(cidr) = item.parse::<ipnet::IpNet>() {
                policy.allowed_cidrs.push(cidr);
            } else if let Ok(ip) = item.parse::<IpAddr>() {
                policy.allowed_ips.insert(ip);
            }
        }

        policy
    }

    pub fn allows_host(&self, host: &str) -> bool {
        if self.allowed_domains.is_empty() {
            return true;
        }

        let host = host.to_ascii_lowercase();
        self.allowed_domains
            .iter()
            .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
    }

    pub fn allows_ip_literal(&self, ip: IpAddr) -> bool {
        if !self.allowed_domains.is_empty() && !self.enforce_ip_policy {
            return false;
        }
        self.allows_ip(ip)
    }

    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
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
    use super::OutboundPolicy;

    #[test]
    fn blocks_ip_literals_when_only_domains_are_configured() {
        let mut net = can_policy::config::NetworkConfig::default();
        net.allow_domains.push("hex.pm".to_string());
        let policy = OutboundPolicy::from_config(&net);

        assert!(!policy.allows_ip_literal("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn allows_subdomains_of_allowed_domain() {
        let mut net = can_policy::config::NetworkConfig::default();
        net.allow_domains.push("hex.pm".to_string());
        let policy = OutboundPolicy::from_config(&net);

        assert!(policy.allows_host("hex.pm"));
        assert!(policy.allows_host("repo.hex.pm"));
        assert!(!policy.allows_host("google.com"));
    }
}
