use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use super::outbound::ip_in_cidr;

/// Policy for the supervisor to enforce.
#[derive(Debug, Clone)]
pub struct NotifierPolicy {
    /// Allowed destination IP addresses for connect()/sendto()/sendmsg().
    pub allowed_ips: HashSet<IpAddr>,

    /// Allowed destination CIDR ranges (stored as `(network, prefix_len)`).
    pub allowed_cidrs: Vec<(IpAddr, u8)>,

    /// Allowed executable paths for execve()/execveat() — exact matches.
    pub allowed_exec_paths: HashSet<PathBuf>,

    /// Allowed executable path prefixes for execve()/execveat().
    /// Entries from `allow_execve` that end in `/*` are stored here as
    /// the prefix (without the trailing `/*`). A path matches if it
    /// starts with the prefix followed by `/`.
    pub allowed_exec_prefixes: Vec<PathBuf>,

    /// Whether to allow `AF_UNIX` sockets.
    pub allow_af_unix: bool,

    /// Whether to allow `AF_INET` / `AF_INET6` sockets.
    pub allow_af_inet: bool,

    /// Whether to restrict outbound IP connections.
    ///
    /// When `true`, outbound `connect()`/`sendto()`/`sendmsg()` to
    /// `AF_INET`/`AF_INET6` destinations are checked against
    /// `allowed_ips`, `allowed_cidrs`, `allowed_domains`, and the
    /// dynamic allowlist.
    ///
    /// When `false` (port-forwarding-only configs with no explicit
    /// domain or IP allowlist), all outbound IP traffic is permitted.
    /// The notifier still enforces clone/socket/execve policy.
    pub restrict_outbound: bool,

    /// The DNS server address configured inside the namespace by pasta.
    ///
    /// This may be the real upstream DNS (detected from systemd-resolved)
    /// or the fallback `PASTA_DNS_ADDR` link-local address. The notifier
    /// uses this to:
    /// - Recognize connect()/sendto() to the DNS server and allow it
    /// - Send supervisor-side DNS queries to this address for
    ///   `resolve_and_add()` (dynamic allowlist population)
    pub dns_server_addr: String,

    /// Domains configured in policy for dynamic DNS resolution.
    pub allowed_domains: Vec<String>,

    /// Shared DNS cache used for TTL-aware refresh of domain → IP mappings.
    pub dns_cache: Option<can_net::dns_cache::DnsCache>,

    /// Dynamic IP allowlist populated from DNS cache lookups.
    pub dynamic_ips: Arc<RwLock<HashSet<IpAddr>>>,

    /// Whether outbound INET/INET6 traffic must go through the local proxy.
    pub enforce_proxy_egress: bool,

    /// Local proxy listening port inside the sandbox namespace.
    pub proxy_port: Option<u16>,
}

impl Default for NotifierPolicy {
    fn default() -> Self {
        Self {
            allowed_ips: HashSet::new(),
            allowed_cidrs: Vec::new(),
            allowed_exec_paths: HashSet::new(),
            allowed_exec_prefixes: Vec::new(),
            allow_af_unix: true,
            allow_af_inet: true,
            restrict_outbound: true,
            dns_server_addr: can_net::pasta::PASTA_DNS_ADDR.to_string(),
            allowed_domains: Vec::new(),
            dns_cache: None,
            dynamic_ips: Arc::new(RwLock::new(HashSet::new())),
            enforce_proxy_egress: false,
            proxy_port: None,
        }
    }
}

impl NotifierPolicy {
    /// Check whether an IP address is allowed by the policy.
    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        // Always allow loopback.
        if ip.is_loopback() {
            return true;
        }
        // Check explicit IPs.
        if self.allowed_ips.contains(&ip) {
            return true;
        }
        // Check the dynamic (DNS-driven) allowlist.
        if let Ok(guard) = self.dynamic_ips.read() {
            if guard.contains(&ip) {
                return true;
            }
        }
        // Check CIDR ranges.
        for &(network, prefix_len) in &self.allowed_cidrs {
            if ip_in_cidr(ip, network, prefix_len) {
                return true;
            }
        }
        false
    }
}
