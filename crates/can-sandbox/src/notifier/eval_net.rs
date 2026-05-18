//! Per-syscall evaluators for the network-touching syscalls
//! (`connect`, `sendto`, `sendmsg`) plus the DNS-refresh hook.
//!
//! Each `evaluate_*` reads the syscall args (via `read_proc_mem` for
//! pointer arguments), does a TOCTOU validity check, then delegates to
//! a pure `classify_*` function that takes the raw `sockaddr` bytes.
//! The pure classifiers are unit-tested directly.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;

use super::abi::SeccompNotif;
use super::outbound::classify_outbound_ip;
use super::policy::NotifierPolicy;
use super::proc_mem::read_proc_mem;
use super::supervisor::{Verdict, is_notif_id_valid};

/// Evaluate a `connect()` syscall.
///
/// `connect(fd, addr, addrlen)`:
///   args[0] = fd
///   args[1] = pointer to sockaddr
///   args[2] = addrlen
pub(super) fn evaluate_connect(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;
    let addr_ptr = notif.data.args[1];
    let addr_len = notif.data.args[2] as usize;

    if !(2..=128).contains(&addr_len) {
        tracing::warn!(pid, addr_len, "connect: suspicious addr_len, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }

    let addr_bytes = match read_proc_mem(pid, addr_ptr, addr_len) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "connect: failed to read sockaddr, denying");
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(
            pid,
            id = notif.id,
            "connect: notification invalidated (TOCTOU)"
        );
        return Verdict::Deny(libc::EPERM as u32);
    }

    let verdict = classify_connect_addr(pid, &addr_bytes, addr_len, policy);
    maybe_refresh_dynamic_allowlist_on_deny(policy, &verdict);
    if matches!(verdict, Verdict::Deny(_)) {
        classify_connect_addr(pid, &addr_bytes, addr_len, policy)
    } else {
        verdict
    }
}

/// Re-resolve all allowed domains on a connect-denied verdict. This
/// catches the case where a TCP DNS path or other resolver bypassed
/// sendto/sendmsg interception, so the dynamic allowlist hadn't
/// updated yet.
pub(super) fn maybe_refresh_dynamic_allowlist_on_deny(policy: &NotifierPolicy, verdict: &Verdict) {
    if !matches!(verdict, Verdict::Deny(_)) {
        return;
    }
    let Some(cache) = &policy.dns_cache else {
        return;
    };

    let mut refreshed = HashSet::new();
    for domain in &policy.allowed_domains {
        if let Some(ips) = cache.resolve_cached_or_lookup(domain) {
            refreshed.extend(ips);
        }
    }

    if let Ok(mut guard) = policy.dynamic_ips.write() {
        *guard = refreshed;
    }
}

/// Classify a `connect()` destination address.
///
/// Pure function: takes the raw `sockaddr` bytes and the policy,
/// returns a verdict. No process-state side effects — directly
/// unit-testable with synthetic byte buffers.
pub(super) fn classify_connect_addr(
    pid: u32,
    addr_bytes: &[u8],
    addr_len: usize,
    policy: &NotifierPolicy,
) -> Verdict {
    let sa_family = u16::from_ne_bytes([addr_bytes[0], addr_bytes[1]]);

    // When outbound restrictions are disabled, allow all IP-family
    // connections without further inspection.
    if !policy.restrict_outbound {
        match sa_family as i32 {
            libc::AF_INET | libc::AF_INET6 => {
                tracing::debug!(
                    pid,
                    family = sa_family,
                    "connect: outbound unrestricted, allowing"
                );
                return Verdict::Allow;
            }
            _ => {}
        }
    }

    if policy.enforce_proxy_egress {
        return classify_proxy_only_connect(pid, addr_bytes, addr_len, sa_family, policy);
    }

    match sa_family as i32 {
        libc::AF_UNSPEC => {
            tracing::debug!(pid, "connect: AF_UNSPEC (disconnect/probe), allowing");
            Verdict::Allow
        }
        libc::AF_UNIX => {
            tracing::debug!(pid, "connect: AF_UNIX, allowing");
            Verdict::Allow
        }
        libc::AF_INET => {
            if addr_len < 8 {
                tracing::warn!(pid, "connect: AF_INET but addr too short");
                return Verdict::Deny(libc::EPERM as u32);
            }
            let port = u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]);
            let ip = Ipv4Addr::new(addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7]);
            let ip_addr = IpAddr::V4(ip);

            if ip.is_unspecified() {
                tracing::debug!(pid, port, "connect: IPv4 unspecified (0.0.0.0), allowing");
                return Verdict::Allow;
            }
            if ip.is_multicast() {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv4 multicast, denying");
                return Verdict::Deny(libc::EACCES as u32);
            }

            if let Ok(dns_ip) = policy.dns_server_addr.parse::<IpAddr>() {
                if ip_addr == dns_ip {
                    tracing::debug!(pid, %ip_addr, port, "connect: DNS server address, allowing");
                    return Verdict::Allow;
                }
            }

            if ip.is_link_local() {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv4 link-local, denying");
                return Verdict::Deny(libc::EACCES as u32);
            }
            if ip.is_broadcast() {
                tracing::warn!(pid, port, "connect: IPv4 broadcast, denying");
                return Verdict::Deny(libc::EACCES as u32);
            }

            if policy.is_ip_allowed(ip_addr) {
                tracing::debug!(pid, %ip_addr, port, "connect: IPv4 allowed");
                Verdict::Allow
            } else {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv4 denied by policy");
                Verdict::Deny(libc::EACCES as u32)
            }
        }
        libc::AF_INET6 => {
            if addr_len < 24 {
                tracing::warn!(pid, "connect: AF_INET6 but addr too short");
                return Verdict::Deny(libc::EPERM as u32);
            }
            let port = u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]);
            let mut addr_buf = [0u8; 16];
            addr_buf.copy_from_slice(&addr_bytes[8..24]);
            let ip = Ipv6Addr::from(addr_buf);
            let ip_addr = IpAddr::V6(ip);

            if ip.is_unspecified() {
                tracing::debug!(pid, port, "connect: IPv6 unspecified (::), allowing");
                return Verdict::Allow;
            }
            if ip.is_multicast() {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv6 multicast, denying");
                return Verdict::Deny(libc::EACCES as u32);
            }
            let segments = ip.segments();
            if segments[0] & 0xffc0 == 0xfe80 {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv6 link-local, denying");
                return Verdict::Deny(libc::EACCES as u32);
            }

            if policy.is_ip_allowed(ip_addr) {
                tracing::debug!(pid, %ip_addr, port, "connect: IPv6 allowed");
                Verdict::Allow
            } else {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv6 denied by policy");
                Verdict::Deny(libc::EACCES as u32)
            }
        }
        other => {
            if other == libc::AF_NETLINK {
                tracing::debug!(pid, "connect: AF_NETLINK, allowing (kernel queries)");
                return Verdict::Allow;
            }
            tracing::warn!(
                pid,
                family = other,
                "connect: unknown address family, denying"
            );
            Verdict::Deny(libc::EPERM as u32)
        }
    }
}

/// In proxy-only egress mode, the only allowed destinations are
/// loopback:proxy_port and the namespace DNS server on port 53.
pub(super) fn classify_proxy_only_connect(
    pid: u32,
    addr_bytes: &[u8],
    addr_len: usize,
    sa_family: u16,
    policy: &NotifierPolicy,
) -> Verdict {
    match sa_family as i32 {
        libc::AF_UNSPEC => Verdict::Allow,
        libc::AF_UNIX => Verdict::Allow,
        libc::AF_INET => {
            if addr_len < 8 {
                return Verdict::Deny(libc::EPERM as u32);
            }
            let port = u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]);
            let ip = Ipv4Addr::new(addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7]);
            let ip_addr = IpAddr::V4(ip);

            if let Ok(dns_ip) = policy.dns_server_addr.parse::<IpAddr>() {
                if ip_addr == dns_ip && port == 53 {
                    return Verdict::Allow;
                }
            }
            if ip_addr.is_loopback() && Some(port) == policy.proxy_port {
                return Verdict::Allow;
            }

            tracing::warn!(pid, %ip_addr, port, "connect: denied (proxy-only egress mode)");
            Verdict::Deny(libc::EACCES as u32)
        }
        libc::AF_INET6 => {
            if addr_len < 24 {
                return Verdict::Deny(libc::EPERM as u32);
            }
            let port = u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]);
            let mut addr_buf = [0u8; 16];
            addr_buf.copy_from_slice(&addr_bytes[8..24]);
            let ip = Ipv6Addr::from(addr_buf);
            let ip_addr = IpAddr::V6(ip);

            if let Ok(dns_ip) = policy.dns_server_addr.parse::<IpAddr>() {
                if ip_addr == dns_ip && port == 53 {
                    return Verdict::Allow;
                }
            }
            if ip_addr.is_loopback() && Some(port) == policy.proxy_port {
                return Verdict::Allow;
            }

            tracing::warn!(pid, %ip_addr, port, "connect: denied (proxy-only egress mode)");
            Verdict::Deny(libc::EACCES as u32)
        }
        libc::AF_NETLINK => Verdict::Allow,
        _ => Verdict::Deny(libc::EPERM as u32),
    }
}

/// Evaluate a `sendto()` syscall.
///
/// `sendto(fd, buf, len, flags, dest_addr, addrlen)`:
///   args[0] = fd
///   args[1] = buf pointer
///   args[2] = len
///   args[3] = flags
///   args[4] = dest_addr pointer
///   args[5] = addrlen
///
/// NULL `dest_addr` (args[4] == 0) means the socket was previously
/// connected — destination was checked then. Allow.
pub(super) fn evaluate_sendto(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;
    let dest_addr_ptr = notif.data.args[4];
    let addr_len = notif.data.args[5] as usize;

    if dest_addr_ptr == 0 {
        tracing::debug!(pid, "sendto: NULL dest_addr (connected socket), allowing");
        return Verdict::Allow;
    }

    if !(2..=128).contains(&addr_len) {
        tracing::warn!(pid, addr_len, "sendto: suspicious addr_len, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }

    let addr_bytes = match read_proc_mem(pid, dest_addr_ptr, addr_len) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "sendto: failed to read sockaddr, denying");
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(pid, "sendto: notification invalidated (TOCTOU)");
        return Verdict::Deny(libc::EPERM as u32);
    }

    classify_sendto_addr(pid, &addr_bytes, addr_len, policy)
}

/// Pure verdict computation for sendto, given pre-read sockaddr bytes.
pub(super) fn classify_sendto_addr(
    pid: u32,
    addr_bytes: &[u8],
    addr_len: usize,
    policy: &NotifierPolicy,
) -> Verdict {
    if addr_len < 2 {
        tracing::warn!(pid, addr_len, "sendto: addr too short, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }
    let sa_family = u16::from_ne_bytes([addr_bytes[0], addr_bytes[1]]);

    if !policy.restrict_outbound {
        match sa_family as i32 {
            libc::AF_INET | libc::AF_INET6 => {
                tracing::debug!(
                    pid,
                    family = sa_family,
                    "sendto: outbound unrestricted, allowing"
                );
                return Verdict::Allow;
            }
            _ => {}
        }
    }

    let (port, ip_addr) = match sa_family as i32 {
        libc::AF_INET => {
            if addr_len < 8 {
                tracing::warn!(pid, "sendto: AF_INET addr too short");
                return Verdict::Deny(libc::EPERM as u32);
            }
            let port = u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]);
            let ip = Ipv4Addr::new(addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7]);
            (port, IpAddr::V4(ip))
        }
        libc::AF_INET6 => {
            if addr_len < 24 {
                tracing::warn!(pid, "sendto: AF_INET6 addr too short");
                return Verdict::Deny(libc::EPERM as u32);
            }
            let port = u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]);
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&addr_bytes[8..24]);
            let ip = Ipv6Addr::from(buf);
            (port, IpAddr::V6(ip))
        }
        libc::AF_UNIX => {
            tracing::debug!(pid, "sendto: AF_UNIX, allowing");
            return Verdict::Allow;
        }
        libc::AF_UNSPEC => {
            tracing::debug!(pid, "sendto: AF_UNSPEC, allowing");
            return Verdict::Allow;
        }
        other => {
            if other == libc::AF_NETLINK {
                tracing::debug!(pid, "sendto: AF_NETLINK, allowing (kernel queries)");
                return Verdict::Allow;
            }
            tracing::warn!(
                pid,
                family = other,
                "sendto: unknown address family, denying"
            );
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    if policy.enforce_proxy_egress {
        if let Ok(dns_ip) = policy.dns_server_addr.parse::<IpAddr>() {
            if ip_addr == dns_ip && port == 53 {
                return Verdict::Allow;
            }
        }
        if ip_addr.is_loopback() && Some(port) == policy.proxy_port {
            return Verdict::Allow;
        }
        tracing::warn!(pid, %ip_addr, port, "sendto: denied (proxy-only egress mode)");
        return Verdict::Deny(libc::EACCES as u32);
    }

    classify_outbound_ip(pid, ip_addr, port, policy, "sendto")
}

/// Evaluate a `sendmsg()` syscall.
///
/// `sendmsg(fd, msghdr *msg, flags)`:
///   args[0] = fd
///   args[1] = pointer to struct msghdr
///   args[2] = flags
pub(super) fn evaluate_sendmsg(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;
    let msghdr_ptr = notif.data.args[1];

    // Read the first 48 bytes of struct msghdr (x86_64 layout):
    //   void         *msg_name;       // offset  0, 8 bytes
    //   socklen_t     msg_namelen;     // offset  8, 4 bytes (+4 padding)
    //   struct iovec *msg_iov;         // offset 16, 8 bytes
    //   size_t        msg_iovlen;      // offset 24, 8 bytes
    //   void         *msg_control;     // offset 32, 8 bytes
    //   size_t        msg_controllen;  // offset 40, 8 bytes
    let hdr_bytes = match read_proc_mem(pid, msghdr_ptr, 48) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "sendmsg: failed to read msghdr, denying");
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    // SAFETY-UNWRAP: hdr_bytes is exactly 48 bytes; the fixed slices
    // match u64/u32 exactly.
    let msg_name_ptr = u64::from_ne_bytes(hdr_bytes[0..8].try_into().unwrap());
    let msg_namelen = u32::from_ne_bytes(hdr_bytes[8..12].try_into().unwrap()) as usize;
    let msg_controllen = u64::from_ne_bytes(hdr_bytes[40..48].try_into().unwrap());

    let msg_name_bytes = if msg_name_ptr != 0 && (2..=128).contains(&msg_namelen) {
        match read_proc_mem(pid, msg_name_ptr, msg_namelen) {
            Ok(b) => Some(b),
            Err(e) => {
                tracing::warn!(pid, error = %e, "sendmsg: failed to read msg_name, denying");
                return Verdict::Deny(libc::EPERM as u32);
            }
        }
    } else {
        None
    };

    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(pid, "sendmsg: notification invalidated (TOCTOU)");
        return Verdict::Deny(libc::EPERM as u32);
    }

    classify_sendmsg(
        pid,
        msg_name_ptr,
        msg_namelen,
        msg_controllen,
        msg_name_bytes.as_deref(),
        policy,
    )
}

/// Pure verdict computation for sendmsg, given pre-read msghdr fields
/// and (optionally) the msg_name buffer.
///
/// Defense-in-depth: ancillary data (`msg_controllen > 0`) on
/// non-AF_UNIX sockets is rejected as a belt-and-suspenders guard
/// against SCM_RIGHTS fd injection. The kernel itself rejects
/// SCM_RIGHTS on non-AF_UNIX, but the early reject here gives a clear
/// log line.
pub(super) fn classify_sendmsg(
    pid: u32,
    msg_name_ptr: u64,
    msg_namelen: usize,
    msg_controllen: u64,
    msg_name_bytes: Option<&[u8]>,
    policy: &NotifierPolicy,
) -> Verdict {
    if msg_controllen > 0 {
        if msg_name_ptr != 0 && msg_namelen >= 2 {
            let Some(addr) = msg_name_bytes else {
                tracing::warn!(
                    pid,
                    msg_controllen,
                    "sendmsg: ancillary data with unreadable msg_name, denying"
                );
                return Verdict::Deny(libc::EPERM as u32);
            };
            if addr.len() < 2 {
                tracing::warn!(
                    pid,
                    msg_controllen,
                    addr_len = addr.len(),
                    "sendmsg: ancillary data with truncated msg_name, denying"
                );
                return Verdict::Deny(libc::EPERM as u32);
            }
            let sa_family = u16::from_ne_bytes([addr[0], addr[1]]);
            if sa_family != libc::AF_UNIX as u16 {
                tracing::warn!(
                    pid,
                    msg_controllen,
                    sa_family,
                    "sendmsg: ancillary data on non-AF_UNIX socket, denying"
                );
                return Verdict::Deny(libc::EPERM as u32);
            }
        }
        tracing::debug!(
            pid,
            msg_controllen,
            "sendmsg: ancillary data on AF_UNIX/connected socket, allowing"
        );
        return Verdict::Allow;
    }

    if !policy.restrict_outbound {
        tracing::debug!(pid, "sendmsg: outbound unrestricted, allowing");
        return Verdict::Allow;
    }

    if msg_name_ptr == 0 {
        tracing::debug!(pid, "sendmsg: NULL msg_name (connected socket), allowing");
        return Verdict::Allow;
    }
    if !(2..=128).contains(&msg_namelen) {
        tracing::warn!(pid, msg_namelen, "sendmsg: suspicious msg_namelen, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }

    let Some(addr_bytes) = msg_name_bytes else {
        tracing::warn!(pid, "sendmsg: msg_name unreadable, denying");
        return Verdict::Deny(libc::EPERM as u32);
    };

    classify_sendto_addr(pid, addr_bytes, msg_namelen, policy)
}
