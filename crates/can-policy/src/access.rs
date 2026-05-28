use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use ipnet::IpNet;

use crate::config::{EgressMode, FilesystemConfig, NetworkConfig};

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

    // Check read list (read-only).
    for allowed in &config.read {
        if path.starts_with(allowed) {
            return AccessDecision::Allow;
        }
    }

    // Check write list (writable).
    for allowed in &config.write {
        if path.starts_with(allowed) {
            return AccessDecision::Allow;
        }
    }

    // Default: deny.
    AccessDecision::Deny
}

/// Check whether a domain is allowed under the active egress mode
/// and the supplied allow-list. The allow-list comes from the
/// `[[host]]` table (via `SandboxConfig::hosts`).
pub fn check_domain(
    domain: &str,
    egress: EgressMode,
    allowed_domains: impl IntoIterator<Item = impl AsRef<str>>,
) -> AccessDecision {
    if matches!(egress, EgressMode::Direct) {
        return AccessDecision::Allow;
    }

    let normalized = domain.trim_end_matches('.');

    for allowed in allowed_domains {
        let allowed_normalized = allowed.as_ref().trim_end_matches('.');
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
    if matches!(config.egress(), EgressMode::Direct) {
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
    use crate::config::EgressMode;

    #[test]
    fn path_allowed() {
        let config = FilesystemConfig {
            read: vec![PathBuf::from("/usr/lib"), PathBuf::from("/tmp/workspace")],
            write: vec![],
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
            read: vec![PathBuf::from("/etc")],
            write: vec![],
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
        let allowed = ["pypi.org".to_string()];
        assert_eq!(
            check_domain("pypi.org", EgressMode::ProxyOnly, &allowed),
            AccessDecision::Allow
        );
        assert_eq!(
            check_domain("files.pypi.org", EgressMode::ProxyOnly, &allowed),
            AccessDecision::Allow
        );
        assert_eq!(
            check_domain("evil.com", EgressMode::ProxyOnly, &allowed),
            AccessDecision::Deny
        );
    }

    #[test]
    fn domain_allow_all_when_egress_direct() {
        let allowed: [String; 0] = [];
        assert_eq!(
            check_domain("anything.com", EgressMode::Direct, &allowed),
            AccessDecision::Allow
        );
    }

    fn net(ips: Vec<&str>) -> NetworkConfig {
        NetworkConfig {
            egress: Some(EgressMode::ProxyOnly),
            allow_ips: ips.into_iter().map(String::from).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn ip_allowed() {
        let config = net(vec!["10.0.0.1"]);
        assert_eq!(check_ip("10.0.0.1", &config), AccessDecision::Allow);
        assert_eq!(check_ip("192.168.1.1", &config), AccessDecision::Deny);
    }

    #[test]
    fn ip_cidr_match() {
        let config = net(vec!["10.0.0.0/8", "192.168.1.0/24"]);
        assert_eq!(check_ip("10.0.0.1", &config), AccessDecision::Allow);
        assert_eq!(check_ip("10.255.255.255", &config), AccessDecision::Allow);
        assert_eq!(check_ip("192.168.1.42", &config), AccessDecision::Allow);
        assert_eq!(check_ip("192.168.2.1", &config), AccessDecision::Deny);
        assert_eq!(check_ip("172.16.0.1", &config), AccessDecision::Deny);
    }

    #[test]
    fn ip_invalid_input_denied() {
        let config = net(vec!["10.0.0.0/8"]);
        assert_eq!(check_ip("not-an-ip", &config), AccessDecision::Deny);
    }

    #[test]
    fn ip_ipv6_cidr() {
        let config = net(vec!["fd00::/8"]);
        assert_eq!(check_ip("fd00::1", &config), AccessDecision::Allow);
        assert_eq!(check_ip("2001:db8::1", &config), AccessDecision::Deny);
    }
}
