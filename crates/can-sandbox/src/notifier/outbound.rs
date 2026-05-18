//! Shared classification for outbound IP destinations + CIDR matching.
//!
//! `classify_outbound_ip` is called by both the `connect()` and the
//! `sendto()`/`sendmsg()` evaluators after they've extracted the
//! destination IP+port from the syscall args. It applies the common
//! "allow loopback / DNS / explicit allowlist; deny multicast /
//! link-local / broadcast / unlisted" policy.

use std::net::IpAddr;

use super::policy::NotifierPolicy;
use super::supervisor::Verdict;

/// Shared IP classification for outbound traffic (connect, sendto, sendmsg).
///
/// Allows loopback, unspecified, and pasta infrastructure addresses;
/// checks the destination IP against the static policy and dynamic
/// allowlist; denies multicast, link-local, and broadcast.
pub(super) fn classify_outbound_ip(
    pid: u32,
    ip_addr: IpAddr,
    port: u16,
    policy: &NotifierPolicy,
    syscall_name: &str,
) -> Verdict {
    if ip_addr.is_loopback() {
        tracing::debug!(pid, %ip_addr, port, "{syscall_name}: loopback, allowing");
        return Verdict::Allow;
    }

    if ip_addr.is_unspecified() {
        tracing::debug!(pid, port, "{syscall_name}: unspecified addr, allowing");
        return Verdict::Allow;
    }

    // Block multicast.
    match ip_addr {
        IpAddr::V4(ip) if ip.is_multicast() => {
            tracing::warn!(pid, %ip_addr, port, "{syscall_name}: multicast, denying");
            return Verdict::Deny(libc::EACCES as u32);
        }
        IpAddr::V6(ip) if ip.is_multicast() => {
            tracing::warn!(pid, %ip_addr, port, "{syscall_name}: multicast, denying");
            return Verdict::Deny(libc::EACCES as u32);
        }
        _ => {}
    }

    // Allow namespace DNS server address.
    if let Ok(dns_ip) = policy.dns_server_addr.parse::<IpAddr>() {
        if ip_addr == dns_ip {
            tracing::debug!(pid, %ip_addr, port, "{syscall_name}: DNS server address, allowing");
            return Verdict::Allow;
        }
    }

    // Block link-local (except pasta DNS already handled above).
    match ip_addr {
        IpAddr::V4(ip) if ip.is_link_local() => {
            tracing::warn!(pid, %ip_addr, port, "{syscall_name}: link-local, denying");
            return Verdict::Deny(libc::EACCES as u32);
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            if segments[0] & 0xffc0 == 0xfe80 {
                tracing::warn!(pid, %ip_addr, port, "{syscall_name}: IPv6 link-local, denying");
                return Verdict::Deny(libc::EACCES as u32);
            }
        }
        _ => {}
    }

    // Block IPv4 broadcast.
    if let IpAddr::V4(ip) = ip_addr {
        if ip.is_broadcast() {
            tracing::warn!(pid, port, "{syscall_name}: broadcast, denying");
            return Verdict::Deny(libc::EACCES as u32);
        }
    }

    // Check static policy.
    if policy.is_ip_allowed(ip_addr) {
        tracing::debug!(pid, %ip_addr, port, "{syscall_name}: allowed");
        Verdict::Allow
    } else {
        tracing::warn!(pid, %ip_addr, port, "{syscall_name}: denied by policy");
        Verdict::Deny(libc::EACCES as u32)
    }
}

/// Check if an IP address falls within a CIDR range.
pub(super) fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix_len > 32 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix_len > 128 {
                return false;
            }
            if prefix_len == 0 {
                return true;
            }
            let ip_bits = u128::from(ip);
            let net_bits = u128::from(net);
            let mask = u128::MAX << (128 - prefix_len);
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false, // V4 vs V6 mismatch
    }
}
