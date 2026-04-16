use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use ipnet::IpNet;

use crate::config::{FilesystemConfig, NetworkConfig};

/// Result of an access policy check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// Access is allowed by policy.
    Allow,
    /// Access is denied by policy.
    Deny,
}

/// Check whether a filesystem path is allowed by the given policy.
///
/// Deny rules are checked first. Then allow and allow_write rules.
/// If neither matches, access is denied (default-deny).
pub fn check_path(path: &Path, config: &FilesystemConfig) -> AccessDecision {
    // Check deny list first.
    for denied in &config.deny {
        if path.starts_with(denied) {
            return AccessDecision::Deny;
        }
    }

    // Check allow list (read-only).
    for allowed in &config.allow {
        if path.starts_with(allowed) {
            return AccessDecision::Allow;
        }
    }

    // Check allow_write list (writable).
    for allowed in &config.allow_write {
        if path.starts_with(allowed) {
            return AccessDecision::Allow;
        }
    }

    // Default: deny.
    AccessDecision::Deny
}

/// Check whether a domain is allowed by the network config.
pub fn check_domain(domain: &str, config: &NetworkConfig) -> AccessDecision {
    if !config.deny_all() {
        return AccessDecision::Allow;
    }

    let normalized = domain.trim_end_matches('.');

    for allowed in &config.allow_domains {
        let allowed_normalized = allowed.trim_end_matches('.');
        if normalized == allowed_normalized
            || normalized.ends_with(&format!(".{allowed_normalized}"))
        {
            return AccessDecision::Allow;
        }
    }

    AccessDecision::Deny
}

/// Check whether an IP address is allowed by the network config.
///
/// Supports both exact IP matches and CIDR notation (e.g., `10.0.0.0/8`).
pub fn check_ip(ip: &str, config: &NetworkConfig) -> AccessDecision {
    if !config.deny_all() {
        return AccessDecision::Allow;
    }

    let addr: IpAddr = match IpAddr::from_str(ip) {
        Ok(a) => a,
        Err(_) => return AccessDecision::Deny,
    };

    for allowed in &config.allow_ips {
        // Try parsing as a CIDR network first, then as an exact IP.
        if let Ok(network) = IpNet::from_str(allowed) {
            if network.contains(&addr) {
                return AccessDecision::Allow;
            }
        } else if let Ok(exact) = IpAddr::from_str(allowed) {
            if addr == exact {
                return AccessDecision::Allow;
            }
        }
    }

    AccessDecision::Deny
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn path_allowed() {
        let config = FilesystemConfig {
            allow: vec![PathBuf::from("/usr/lib"), PathBuf::from("/tmp/workspace")],
            allow_write: vec![],
            deny: vec![],
            mask: vec![],
        };
        assert_eq!(
            check_path(Path::new("/usr/lib/python3"), &config),
            AccessDecision::Allow
        );
        assert_eq!(
            check_path(Path::new("/tmp/workspace/foo.py"), &config),
            AccessDecision::Allow
        );
        assert_eq!(
            check_path(Path::new("/etc/passwd"), &config),
            AccessDecision::Deny
        );
    }

    #[test]
    fn path_deny_overrides_allow() {
        let config = FilesystemConfig {
            allow: vec![PathBuf::from("/etc")],
            allow_write: vec![],
            deny: vec![PathBuf::from("/etc/shadow")],
            mask: vec![],
        };
        assert_eq!(
            check_path(Path::new("/etc/hostname"), &config),
            AccessDecision::Allow
        );
        assert_eq!(
            check_path(Path::new("/etc/shadow"), &config),
            AccessDecision::Deny
        );
    }

    #[test]
    fn domain_allowed() {
        let config = NetworkConfig {
            allow_domains: vec!["pypi.org".to_string()],
            allow_ips: vec![],
            deny_all: Some(true),
            ports: vec![],
        };
        assert_eq!(check_domain("pypi.org", &config), AccessDecision::Allow);
        assert_eq!(
            check_domain("files.pypi.org", &config),
            AccessDecision::Allow
        );
        assert_eq!(check_domain("evil.com", &config), AccessDecision::Deny);
    }

    #[test]
    fn domain_allow_all_when_deny_all_false() {
        let config = NetworkConfig {
            allow_domains: vec![],
            allow_ips: vec![],
            deny_all: Some(false),
            ports: vec![],
        };
        assert_eq!(check_domain("anything.com", &config), AccessDecision::Allow);
    }

    #[test]
    fn ip_allowed() {
        let config = NetworkConfig {
            allow_domains: vec![],
            allow_ips: vec!["10.0.0.1".to_string()],
            deny_all: Some(true),
            ports: vec![],
        };
        assert_eq!(check_ip("10.0.0.1", &config), AccessDecision::Allow);
        assert_eq!(check_ip("192.168.1.1", &config), AccessDecision::Deny);
    }

    #[test]
    fn ip_cidr_match() {
        let config = NetworkConfig {
            allow_domains: vec![],
            allow_ips: vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()],
            deny_all: Some(true),
            ports: vec![],
        };
        assert_eq!(check_ip("10.0.0.1", &config), AccessDecision::Allow);
        assert_eq!(check_ip("10.255.255.255", &config), AccessDecision::Allow);
        assert_eq!(check_ip("192.168.1.42", &config), AccessDecision::Allow);
        assert_eq!(check_ip("192.168.2.1", &config), AccessDecision::Deny);
        assert_eq!(check_ip("172.16.0.1", &config), AccessDecision::Deny);
    }

    #[test]
    fn ip_invalid_input_denied() {
        let config = NetworkConfig {
            allow_domains: vec![],
            allow_ips: vec!["10.0.0.0/8".to_string()],
            deny_all: Some(true),
            ports: vec![],
        };
        assert_eq!(check_ip("not-an-ip", &config), AccessDecision::Deny);
    }

    #[test]
    fn ip_ipv6_cidr() {
        let config = NetworkConfig {
            allow_domains: vec![],
            allow_ips: vec!["fd00::/8".to_string()],
            deny_all: Some(true),
            ports: vec![],
        };
        assert_eq!(check_ip("fd00::1", &config), AccessDecision::Allow);
        assert_eq!(check_ip("2001:db8::1", &config), AccessDecision::Deny);
    }
}
