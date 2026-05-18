//! Build a `NotifierPolicy` from a `SandboxConfig` plus pre-resolved
//! DNS state.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use can_policy::config::EgressMode;

use super::policy::NotifierPolicy;

/// Build a `NotifierPolicy` from the sandbox configuration and
/// pre-resolved IP addresses.
///
/// `dns_addr` is the DNS server address configured inside the namespace
/// by pasta (either the real upstream DNS or the fallback link-local).
pub fn policy_from_config(
    config: &can_policy::SandboxConfig,
    resolved_ips: &[(String, Vec<IpAddr>)],
    dns_addr: &str,
    dns_cache: Option<can_net::dns_cache::DnsCache>,
    proxy_port: Option<u16>,
) -> NotifierPolicy {
    let mut allowed_ips: HashSet<IpAddr> = HashSet::new();
    let mut allowed_cidrs: Vec<(IpAddr, u8)> = Vec::new();

    // Pre-resolved IPs from allowed domains.
    for (_domain, ips) in resolved_ips {
        for ip in ips {
            allowed_ips.insert(*ip);
        }
    }

    // Explicitly allowed IPs and CIDRs.
    for ip_str in &config.network.allow_ips {
        if let Some((net, prefix)) = parse_cidr(ip_str) {
            allowed_cidrs.push((net, prefix));
        } else if let Ok(ip) = ip_str.parse::<IpAddr>() {
            allowed_ips.insert(ip);
        } else {
            tracing::warn!(ip = ip_str, "could not parse allowed IP/CIDR, skipping");
        }
    }

    // DNS server address — always allowed. The namespace's resolv.conf
    // points to this; actual DNS filtering happens at the query level
    // (domain allowlist check). Also allow the PASTA_DNS_ADDR fallback
    // in case detection differs from the link-local address.
    if let Ok(ip) = dns_addr.parse::<IpAddr>() {
        allowed_ips.insert(ip);
    }
    allowed_ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    allowed_ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    // SAFETY-UNWRAP: PASTA_DNS_ADDR is a const &str whose validity as
    // an IP literal is checked by can_net::pasta tests.
    allowed_ips.insert(can_net::pasta::PASTA_DNS_ADDR.parse().unwrap());

    // Host's default gateway — pasta mirrors the host's network config.
    if let Some(gw) = can_net::pasta::detect_default_gateway() {
        allowed_ips.insert(IpAddr::V4(gw));
        tracing::debug!(gateway = %gw, "added default gateway to notifier allowlist");
    }

    // Allowed exec paths/prefixes. Entries ending in `/*` are prefix
    // rules (match any path under that directory). All others are
    // exact matches.
    let mut allowed_exec_paths: HashSet<PathBuf> = HashSet::new();
    let mut allowed_exec_prefixes: Vec<PathBuf> = Vec::new();

    for p in &config.process.allow_execve {
        let s = p.as_os_str().to_string_lossy();
        if let Some(prefix_str) = s.strip_suffix("/*") {
            let prefix_path = PathBuf::from(prefix_str);
            let canonical = prefix_path
                .canonicalize()
                .unwrap_or_else(|_| prefix_path.clone());
            allowed_exec_prefixes.push(canonical);
        } else {
            let canonical = p.canonicalize().unwrap_or_else(|_| p.clone());
            allowed_exec_paths.insert(canonical);
        }
    }

    // Determine whether to restrict outbound IP connections.
    //
    // Restrict when:
    //   * an explicit allow list is configured (domains or IPs);
    //   * the egress mode is `proxy-only` or `none` (intrinsically
    //     restrictive). Without this term, `egress = "none"` with no
    //     allow lists falls through to the "outbound unrestricted"
    //     branch and the supervisor allows every connect — the exact
    //     bypass we're guarding against.
    //
    // Port-forwarding-only `direct` configs (no domains, no IPs, no
    // explicit restriction) intentionally do NOT set this; the
    // notifier is still useful for clone/socket/execve enforcement but
    // allows raw outbound.
    let egress_mode = config.network.egress();
    let restrict_outbound = !config.network.allow_ips.is_empty()
        || !config.network.allow_domains.is_empty()
        || matches!(egress_mode, EgressMode::ProxyOnly | EgressMode::None);

    NotifierPolicy {
        allowed_ips,
        allowed_cidrs,
        allowed_exec_paths,
        allowed_exec_prefixes,
        allow_af_unix: true,
        allow_af_inet: true,
        restrict_outbound,
        dns_server_addr: dns_addr.to_string(),
        allowed_domains: config.network.allow_domains.clone(),
        dns_cache,
        dynamic_ips: Arc::new(RwLock::new(HashSet::new())),
        // `egress = "none"` and `egress = "proxy-only"` both restrict
        // the worker to a tiny set of addresses; the difference is that
        // proxy-only ALSO whitelists the proxy port. We route both
        // through `classify_proxy_only_connect`, which checks
        // `Some(port) == policy.proxy_port` — when egress is None the
        // proxy isn't started and `proxy_port` is None, so no port
        // matches and everything (except AF_UNIX/AF_UNSPEC) is denied.
        enforce_proxy_egress: matches!(egress_mode, EgressMode::ProxyOnly | EgressMode::None),
        proxy_port,
    }
}

/// Parse a CIDR string like "10.0.0.0/8" into `(network, prefix_len)`.
pub(super) fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: IpAddr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    Some((ip, prefix))
}
