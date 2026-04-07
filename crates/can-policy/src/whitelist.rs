use std::path::Path;

use crate::config::{FilesystemConfig, NetworkConfig};

/// Result of a whitelist check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDecision {
    /// Access is allowed by policy.
    Allow,
    /// Access is denied by policy.
    Deny,
}

/// Check whether a filesystem path is allowed by the given policy.
///
/// Deny rules are checked first. Then allow rules.
/// If neither matches, access is denied (default-deny).
pub fn check_path(path: &Path, config: &FilesystemConfig) -> AccessDecision {
    // Check deny list first.
    for denied in &config.deny {
        if path.starts_with(denied) {
            return AccessDecision::Deny;
        }
    }

    // Check allow list.
    for allowed in &config.allow {
        if path.starts_with(allowed) {
            return AccessDecision::Allow;
        }
    }

    // Default: deny.
    AccessDecision::Deny
}

/// Check whether a domain is allowed by the network config.
pub fn check_domain(domain: &str, config: &NetworkConfig) -> AccessDecision {
    if !config.deny_all {
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

/// Check whether an IP address (as string) is allowed by the network config.
///
/// Currently supports exact match only. CIDR matching comes in Phase 3.
pub fn check_ip(ip: &str, config: &NetworkConfig) -> AccessDecision {
    if !config.deny_all {
        return AccessDecision::Allow;
    }

    for allowed in &config.allow_ips {
        // TODO(Phase 3): proper CIDR matching
        if ip == allowed {
            return AccessDecision::Allow;
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
            deny: vec![],
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
            deny: vec![PathBuf::from("/etc/shadow")],
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
            deny_all: true,
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
            deny_all: false,
        };
        assert_eq!(check_domain("anything.com", &config), AccessDecision::Allow);
    }

    #[test]
    fn ip_allowed() {
        let config = NetworkConfig {
            allow_domains: vec![],
            allow_ips: vec!["10.0.0.1".to_string()],
            deny_all: true,
        };
        assert_eq!(check_ip("10.0.0.1", &config), AccessDecision::Allow);
        assert_eq!(check_ip("192.168.1.1", &config), AccessDecision::Deny);
    }
}
