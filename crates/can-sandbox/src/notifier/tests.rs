//! Tests for the notifier subsystem. The original 947-line test
//! module was moved here wholesale during the notifier.rs split; the
//! only changes are explicit `use super::...` imports replacing the
//! `use super::*` glob (the new module structure means tests need to
//! reach into per-submodule items).
//!
//! The `field_reassign_with_default` lint is allowed throughout because
//! the original test setup convention is `mut x = NotifierPolicy::default();
//! x.field = ...;`, which makes the diff against the pre-split file
//! easy to audit.

#![allow(clippy::field_reassign_with_default)]
#![allow(unused_imports, dead_code)]

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::abi::{
    AF_INET, AF_INET6, AF_NETLINK, AF_UNIX, CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET,
    CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS, SOCK_RAW,
};
use super::eval_clone::evaluate_clone;
use super::eval_net::{
    classify_connect_addr, classify_proxy_only_connect, classify_sendmsg, classify_sendto_addr,
    maybe_refresh_dynamic_allowlist_on_deny,
};
use super::eval_proc::{evaluate_socket, is_exec_path_allowed};
use super::kernel::parse_kernel_version;
use super::outbound::ip_in_cidr;
use super::policy_config::parse_cidr;
use super::supervisor::Verdict;
use super::*;

/// Build a fresh policy with a small allow_ips set so restrict_outbound
/// kicks in. Used as the default starting point for sendto/connect tests.
fn policy_restricting_to(allowed_ips: &[&str]) -> NotifierPolicy {
    let mut p = NotifierPolicy::default();
    p.restrict_outbound = true;
    for ip in allowed_ips {
        p.allowed_ips.insert(ip.parse().expect("test IP"));
    }
    p
}

/// Build an AF_INET sockaddr_in: 16 bytes of `{family, port_be, ip[4], zero[8]}`.
fn sockaddr_in(ip: [u8; 4], port: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 16];
    buf[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&ip);
    buf
}

/// Build an AF_INET6 sockaddr_in6: 28 bytes.
fn sockaddr_in6(ip: [u8; 16], port: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 28];
    buf[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    // flowinfo (offset 4, 4 bytes) left zero.
    buf[8..24].copy_from_slice(&ip);
    // scope_id (offset 24, 4 bytes) left zero.
    buf
}

fn sockaddr_family_only(family: libc::sa_family_t) -> Vec<u8> {
    family.to_ne_bytes().to_vec()
}

// -----------------------------------------------------------------
// classify_sendto_addr — happy paths
// -----------------------------------------------------------------

#[test]
fn sendto_af_unspec_always_allowed() {
    let policy = policy_restricting_to(&[]);
    let bytes = sockaddr_family_only(libc::AF_UNSPEC as u16);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 2, &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendto_af_unix_always_allowed() {
    let policy = policy_restricting_to(&[]);
    let bytes = sockaddr_family_only(libc::AF_UNIX as u16);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 2, &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendto_af_netlink_always_allowed() {
    let policy = policy_restricting_to(&[]);
    let bytes = sockaddr_family_only(libc::AF_NETLINK as u16);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 2, &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendto_allowed_inet_passes_through_classify_outbound() {
    let policy = policy_restricting_to(&["1.2.3.4"]);
    let bytes = sockaddr_in([1, 2, 3, 4], 443);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 16, &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendto_disallowed_inet_denied() {
    let policy = policy_restricting_to(&["1.2.3.4"]);
    let bytes = sockaddr_in([5, 6, 7, 8], 443);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 16, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendto_unrestricted_allows_arbitrary_inet() {
    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = false;
    let bytes = sockaddr_in([1, 1, 1, 1], 80);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 16, &policy),
        Verdict::Allow
    ));
}

// -----------------------------------------------------------------
// classify_sendto_addr — malformed / hostile input
// -----------------------------------------------------------------

#[test]
fn sendto_rejects_addr_shorter_than_family_field() {
    let policy = policy_restricting_to(&[]);
    let bytes = vec![0x02]; // only one byte; can't even read sa_family
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 1, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendto_rejects_truncated_sockaddr_in() {
    let policy = policy_restricting_to(&["1.2.3.4"]);
    // Family set to AF_INET but only 4 bytes — port read would
    // succeed but the ip read needs offsets 4..8.
    let mut bytes = vec![0u8; 4];
    bytes[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    bytes[2..4].copy_from_slice(&80u16.to_be_bytes());
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 4, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendto_rejects_truncated_sockaddr_in6() {
    let policy = policy_restricting_to(&[]);
    // Family AF_INET6 but length < 24 → ip can't be parsed.
    let mut bytes = vec![0u8; 16];
    bytes[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 16, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendto_unknown_family_denied() {
    let policy = policy_restricting_to(&[]);
    let bytes = sockaddr_family_only(0xbeef);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 2, &policy),
        Verdict::Deny(_)
    ));
}

// -----------------------------------------------------------------
// Proxy-only / egress=none mode
// -----------------------------------------------------------------

#[test]
fn sendto_proxy_only_allows_dns_server() {
    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = true;
    policy.enforce_proxy_egress = true;
    policy.dns_server_addr = "169.254.0.53".to_string();
    let bytes = sockaddr_in([169, 254, 0, 53], 53);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 16, &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendto_proxy_only_allows_loopback_to_proxy_port() {
    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = true;
    policy.enforce_proxy_egress = true;
    policy.proxy_port = Some(8080);
    let bytes = sockaddr_in([127, 0, 0, 1], 8080);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 16, &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendto_proxy_only_denies_loopback_to_other_port() {
    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = true;
    policy.enforce_proxy_egress = true;
    policy.proxy_port = Some(8080);
    let bytes = sockaddr_in([127, 0, 0, 1], 12345);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 16, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendto_egress_none_denies_loopback_when_no_proxy_port() {
    // egress=none policy: enforce_proxy_egress true, proxy_port None.
    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = true;
    policy.enforce_proxy_egress = true;
    policy.proxy_port = None;
    let bytes = sockaddr_in([127, 0, 0, 1], 8080);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 16, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendto_proxy_only_denies_arbitrary_inet() {
    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = true;
    policy.enforce_proxy_egress = true;
    policy.proxy_port = Some(8080);
    let bytes = sockaddr_in([1, 2, 3, 4], 443);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 16, &policy),
        Verdict::Deny(_)
    ));
}

// -----------------------------------------------------------------
// IPv6
// -----------------------------------------------------------------

#[test]
fn sendto_inet6_allowed_when_in_policy() {
    let policy = policy_restricting_to(&["::1"]);
    let mut ip = [0u8; 16];
    ip[15] = 1; // ::1
    let bytes = sockaddr_in6(ip, 443);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 28, &policy),
        Verdict::Allow
    ));
}

// -----------------------------------------------------------------
// classify_sendmsg — ancillary data (SCM_RIGHTS) defense-in-depth
// -----------------------------------------------------------------

#[test]
fn sendmsg_ancillary_on_af_unix_allowed() {
    let policy = NotifierPolicy::default();
    let unix_name = sockaddr_family_only(libc::AF_UNIX as u16);
    assert!(matches!(
        classify_sendmsg(
            42,
            0xdead_beef, // msg_name_ptr non-NULL
            unix_name.len(),
            32, // msg_controllen > 0
            Some(&unix_name),
            &policy,
        ),
        Verdict::Allow
    ));
}

#[test]
fn sendmsg_ancillary_on_af_inet_denied() {
    let policy = NotifierPolicy::default();
    let inet_name = sockaddr_in([1, 2, 3, 4], 80);
    assert!(matches!(
        classify_sendmsg(
            42,
            0xdead_beef,
            inet_name.len(),
            32,
            Some(&inet_name),
            &policy,
        ),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendmsg_ancillary_on_af_inet6_denied() {
    let policy = NotifierPolicy::default();
    let inet6_name = sockaddr_in6([0u8; 16], 80);
    assert!(matches!(
        classify_sendmsg(
            42,
            0xdead_beef,
            inet6_name.len(),
            32,
            Some(&inet6_name),
            &policy,
        ),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendmsg_ancillary_with_null_msg_name_allowed() {
    // Connected socket: msg_name_ptr == 0, ancillary data permitted
    // because the destination was already vetted at connect() time
    // (most likely an AF_UNIX socket between internal processes).
    let policy = NotifierPolicy::default();
    assert!(matches!(
        classify_sendmsg(42, 0, 0, 32, None, &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendmsg_ancillary_with_unreadable_msg_name_denied() {
    // Caller said msg_name_ptr != 0 + msg_namelen >= 2 but failed to
    // read the bytes. We must defensively deny rather than risk
    // letting an SCM_RIGHTS payload through.
    let policy = NotifierPolicy::default();
    assert!(matches!(
        classify_sendmsg(42, 0xdead_beef, 16, 32, None, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendmsg_ancillary_with_truncated_msg_name_denied() {
    // Caller managed to read only 1 byte; we can't determine family.
    let policy = NotifierPolicy::default();
    let truncated = vec![0x01];
    assert!(matches!(
        classify_sendmsg(42, 0xdead_beef, 16, 32, Some(&truncated), &policy),
        Verdict::Deny(_)
    ));
}

// -----------------------------------------------------------------
// classify_sendmsg — non-ancillary path
// -----------------------------------------------------------------

#[test]
fn sendmsg_no_ancillary_unrestricted_allows() {
    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = false;
    let bytes = sockaddr_in([1, 1, 1, 1], 80);
    assert!(matches!(
        classify_sendmsg(42, 0xdead_beef, 16, 0, Some(&bytes), &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendmsg_no_ancillary_null_msg_name_allowed() {
    let policy = policy_restricting_to(&[]);
    assert!(matches!(
        classify_sendmsg(42, 0, 0, 0, None, &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendmsg_no_ancillary_inet_to_allowed_ip_passes() {
    let policy = policy_restricting_to(&["1.2.3.4"]);
    let bytes = sockaddr_in([1, 2, 3, 4], 443);
    assert!(matches!(
        classify_sendmsg(42, 0xdead_beef, 16, 0, Some(&bytes), &policy),
        Verdict::Allow
    ));
}

#[test]
fn sendmsg_no_ancillary_inet_to_disallowed_ip_denied() {
    let policy = policy_restricting_to(&["1.2.3.4"]);
    let bytes = sockaddr_in([5, 6, 7, 8], 443);
    assert!(matches!(
        classify_sendmsg(42, 0xdead_beef, 16, 0, Some(&bytes), &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendmsg_no_ancillary_oversized_namelen_denied() {
    let policy = policy_restricting_to(&[]);
    let bytes = sockaddr_in([1, 2, 3, 4], 80);
    assert!(matches!(
        classify_sendmsg(42, 0xdead_beef, 1024, 0, Some(&bytes), &policy),
        Verdict::Deny(_)
    ));
}

// -----------------------------------------------------------------
// is_exec_path_allowed — exec policy checks
// -----------------------------------------------------------------

fn exec_policy(paths: &[&str], prefixes: &[&str]) -> NotifierPolicy {
    let mut p = NotifierPolicy::default();
    for s in paths {
        p.allowed_exec_paths.insert(PathBuf::from(s));
    }
    for s in prefixes {
        p.allowed_exec_prefixes.push(PathBuf::from(s));
    }
    p
}

#[test]
fn exec_exact_match_allowed() {
    let p = exec_policy(&["/usr/bin/python3.12"], &[]);
    assert!(is_exec_path_allowed(Path::new("/usr/bin/python3.12"), &p));
}

#[test]
fn exec_exact_no_match_denied() {
    let p = exec_policy(&["/usr/bin/python3.12"], &[]);
    assert!(!is_exec_path_allowed(Path::new("/usr/bin/python3.11"), &p));
    assert!(!is_exec_path_allowed(Path::new("/bin/python3.12"), &p));
}

#[test]
fn exec_empty_policy_denies_everything() {
    let p = exec_policy(&[], &[]);
    assert!(!is_exec_path_allowed(Path::new("/usr/bin/sh"), &p));
    assert!(!is_exec_path_allowed(Path::new("/bin/echo"), &p));
}

#[test]
fn exec_prefix_match_with_boundary_allowed() {
    let p = exec_policy(&[], &["/nix/store"]);
    assert!(is_exec_path_allowed(
        Path::new("/nix/store/abc-foo/bin/mix"),
        &p,
    ));
    assert!(is_exec_path_allowed(Path::new("/nix/store/x/y"), &p));
}

#[test]
fn exec_prefix_match_requires_boundary_not_partial() {
    // Critical: prefix "/nix/store" must NOT match "/nix/storage" —
    // the next char after the prefix MUST be '/'. Anything else
    // (including end-of-string) is a partial directory name match
    // and a known sandbox-escape pattern.
    let p = exec_policy(&[], &["/nix/store"]);
    assert!(!is_exec_path_allowed(Path::new("/nix/storage/x"), &p));
    assert!(!is_exec_path_allowed(Path::new("/nix/storex"), &p));
    // Exactly the prefix itself with no trailing slash is also NOT
    // a match — would need to be an exec path which by definition
    // has a binary name component after the directory.
    assert!(!is_exec_path_allowed(Path::new("/nix/store"), &p));
}

#[test]
fn exec_prefix_does_not_subsume_unrelated_paths() {
    let p = exec_policy(&[], &["/nix/store"]);
    assert!(!is_exec_path_allowed(Path::new("/usr/bin/sh"), &p));
    assert!(!is_exec_path_allowed(Path::new("/home/user/bin"), &p));
}

#[test]
fn exec_exact_path_and_prefix_can_coexist() {
    let p = exec_policy(&["/usr/bin/python3.12"], &["/home/user/.local/bin"]);
    assert!(is_exec_path_allowed(Path::new("/usr/bin/python3.12"), &p,));
    assert!(is_exec_path_allowed(
        Path::new("/home/user/.local/bin/myscript"),
        &p,
    ));
    assert!(!is_exec_path_allowed(Path::new("/etc/shadow"), &p));
}

#[test]
fn exec_multiple_prefixes_short_circuit_correctly() {
    let p = exec_policy(&[], &["/a", "/b", "/c/d"]);
    assert!(is_exec_path_allowed(Path::new("/a/x"), &p));
    assert!(is_exec_path_allowed(Path::new("/b/y"), &p));
    assert!(is_exec_path_allowed(Path::new("/c/d/z"), &p));
    // /c alone doesn't match — only /c/d
    assert!(!is_exec_path_allowed(Path::new("/c/x"), &p));
}

// -----------------------------------------------------------------
// evaluate_clone — namespace flag rejection
// -----------------------------------------------------------------

fn clone_args(flags: u64) -> [u64; 6] {
    [flags, 0, 0, 0, 0, 0]
}

#[test]
fn clone_no_flags_allowed() {
    // bare fork (clone with flags = 0) is the everyday case
    assert!(matches!(evaluate_clone(&clone_args(0), 42), Verdict::Allow));
}

#[test]
fn clone_thread_flags_allowed() {
    // CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
    // → standard pthread_create flags, no NS bits
    let flags = 0x100 | 0x200 | 0x400 | 0x800 | 0x0001_0000;
    assert!(matches!(
        evaluate_clone(&clone_args(flags), 42),
        Verdict::Allow
    ));
}

#[test]
fn clone_newuser_denied() {
    assert!(matches!(
        evaluate_clone(&clone_args(CLONE_NEWUSER), 42),
        Verdict::Deny(_)
    ));
}

#[test]
fn clone_newns_denied() {
    assert!(matches!(
        evaluate_clone(&clone_args(CLONE_NEWNS), 42),
        Verdict::Deny(_)
    ));
}

#[test]
fn clone_newpid_denied() {
    assert!(matches!(
        evaluate_clone(&clone_args(CLONE_NEWPID), 42),
        Verdict::Deny(_)
    ));
}

#[test]
fn clone_newnet_denied() {
    assert!(matches!(
        evaluate_clone(&clone_args(CLONE_NEWNET), 42),
        Verdict::Deny(_)
    ));
}

#[test]
fn clone_newipc_denied() {
    assert!(matches!(
        evaluate_clone(&clone_args(CLONE_NEWIPC), 42),
        Verdict::Deny(_)
    ));
}

#[test]
fn clone_newuts_denied() {
    assert!(matches!(
        evaluate_clone(&clone_args(CLONE_NEWUTS), 42),
        Verdict::Deny(_)
    ));
}

#[test]
fn clone_newcgroup_denied() {
    assert!(matches!(
        evaluate_clone(&clone_args(CLONE_NEWCGROUP), 42),
        Verdict::Deny(_)
    ));
}

#[test]
fn clone_newtime_denied() {
    assert!(matches!(
        evaluate_clone(&clone_args(CLONE_NEWTIME), 42),
        Verdict::Deny(_)
    ));
}

#[test]
fn clone_combined_ns_flags_denied() {
    // Each combination of namespace flags must fail, not just the
    // single-flag cases. Otherwise a `CLONE_NEWUSER | CLONE_NEWNS`
    // call could slip through a per-flag exception.
    for combo in [
        CLONE_NEWUSER | CLONE_NEWNS,
        CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET,
        CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS,
    ] {
        assert!(
            matches!(evaluate_clone(&clone_args(combo), 42), Verdict::Deny(_)),
            "expected combo {combo:#x} to be denied",
        );
    }
}

#[test]
fn clone_ns_flag_mixed_with_thread_flags_denied() {
    // Adversarial recipe: mix CLONE_VM | CLONE_THREAD (legitimate
    // thread flags) with CLONE_NEWUSER. Whole call must deny.
    let flags = 0x100 | 0x0001_0000 | CLONE_NEWUSER;
    assert!(matches!(
        evaluate_clone(&clone_args(flags), 42),
        Verdict::Deny(_)
    ));
}

// -----------------------------------------------------------------
// evaluate_socket — domain/type/protocol filtering
// -----------------------------------------------------------------

fn sock_args(domain: u64, sock_type: u64, protocol: u64) -> [u64; 6] {
    [domain, sock_type, protocol, 0, 0, 0]
}

#[test]
fn socket_af_inet_tcp_allowed() {
    let policy = NotifierPolicy::default();
    assert!(matches!(
        evaluate_socket(
            &sock_args(AF_INET, libc::SOCK_STREAM as u64, 0),
            42,
            &policy
        ),
        Verdict::Allow
    ));
}

#[test]
fn socket_af_inet_udp_allowed() {
    let policy = NotifierPolicy::default();
    assert!(matches!(
        evaluate_socket(&sock_args(AF_INET, libc::SOCK_DGRAM as u64, 0), 42, &policy),
        Verdict::Allow
    ));
}

#[test]
fn socket_af_inet6_tcp_allowed() {
    let policy = NotifierPolicy::default();
    assert!(matches!(
        evaluate_socket(
            &sock_args(AF_INET6, libc::SOCK_STREAM as u64, 0),
            42,
            &policy
        ),
        Verdict::Allow
    ));
}

#[test]
fn socket_af_inet_sock_raw_denied() {
    let policy = NotifierPolicy::default();
    assert!(matches!(
        evaluate_socket(
            &sock_args(AF_INET, SOCK_RAW, libc::IPPROTO_ICMP as u64),
            42,
            &policy
        ),
        Verdict::Deny(_)
    ));
}

#[test]
fn socket_af_inet6_sock_raw_denied() {
    let policy = NotifierPolicy::default();
    assert!(matches!(
        evaluate_socket(&sock_args(AF_INET6, SOCK_RAW, 0), 42, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn socket_af_packet_denied() {
    let policy = NotifierPolicy::default();
    const AF_PACKET: u64 = 17;
    assert!(matches!(
        evaluate_socket(&sock_args(AF_PACKET, SOCK_RAW, 0), 42, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn socket_af_netlink_route_allowed() {
    let policy = NotifierPolicy::default();
    const NETLINK_ROUTE: u64 = 0;
    assert!(matches!(
        evaluate_socket(&sock_args(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE), 42, &policy),
        Verdict::Allow
    ));
}

#[test]
fn socket_af_netlink_audit_denied() {
    let policy = NotifierPolicy::default();
    const NETLINK_AUDIT: u64 = 9;
    assert!(matches!(
        evaluate_socket(&sock_args(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT), 42, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn socket_af_netlink_kobject_uevent_denied() {
    let policy = NotifierPolicy::default();
    const NETLINK_KOBJECT_UEVENT: u64 = 15;
    assert!(matches!(
        evaluate_socket(
            &sock_args(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT),
            42,
            &policy
        ),
        Verdict::Deny(_)
    ));
}

#[test]
fn socket_af_unix_allowed_when_policy_allows() {
    let mut policy = NotifierPolicy::default();
    policy.allow_af_unix = true;
    assert!(matches!(
        evaluate_socket(
            &sock_args(AF_UNIX, libc::SOCK_STREAM as u64, 0),
            42,
            &policy
        ),
        Verdict::Allow
    ));
}

#[test]
fn socket_af_unix_denied_when_policy_disallows() {
    let mut policy = NotifierPolicy::default();
    policy.allow_af_unix = false;
    assert!(matches!(
        evaluate_socket(
            &sock_args(AF_UNIX, libc::SOCK_STREAM as u64, 0),
            42,
            &policy
        ),
        Verdict::Deny(_)
    ));
}

#[test]
fn socket_af_inet_denied_when_policy_disallows() {
    let mut policy = NotifierPolicy::default();
    policy.allow_af_inet = false;
    assert!(matches!(
        evaluate_socket(
            &sock_args(AF_INET, libc::SOCK_STREAM as u64, 0),
            42,
            &policy
        ),
        Verdict::Deny(_)
    ));
}

#[test]
fn socket_unknown_domain_denied() {
    let policy = NotifierPolicy::default();
    // AF_BLUETOOTH (31) and friends — not on any allow list
    const AF_BLUETOOTH: u64 = 31;
    assert!(matches!(
        evaluate_socket(
            &sock_args(AF_BLUETOOTH, libc::SOCK_STREAM as u64, 0),
            42,
            &policy
        ),
        Verdict::Deny(_)
    ));
}

// -----------------------------------------------------------------
// Dynamic-allowlist refresh — closes-the-loop integration
// -----------------------------------------------------------------

/// First call to classify_connect_addr is denied. The
/// maybe_refresh_dynamic_allowlist_on_deny side effect populates
/// dynamic_ips from cache. The retry then allows.
///
/// This is the core "domain → dynamic IP → connect allowed" path
/// — broken in this flow, the supervisor never honours a recipe's
/// allow_domains for direct connects.
#[test]
fn dynamic_allowlist_refresh_closes_the_loop() {
    use can_net::dns_cache::DnsCache;
    use std::collections::HashSet;
    use std::time::Duration;

    // Recipe-equivalent state: a supervisor restricting outbound,
    // with one allowed domain and no static IP entries. The cache
    // is pre-seeded as if a prior DNS query had resolved
    // "example.test" → 203.0.113.42.
    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = true;
    policy.allowed_domains = vec!["example.test".to_string()];
    let cache = DnsCache::new(Duration::from_secs(60));
    let mut seeded = HashSet::new();
    seeded.insert("203.0.113.42".parse().unwrap());
    cache.insert_for_testing("example.test", seeded, Duration::from_secs(60));
    policy.dns_cache = Some(cache);

    let addr = sockaddr_in([203, 0, 113, 42], 443);

    // Step 1: dynamic_ips is empty → first verdict must be Deny.
    let v1 = classify_connect_addr(42, &addr, 16, &policy);
    assert!(
        matches!(v1, Verdict::Deny(_)),
        "expected initial deny when dynamic_ips empty, got {v1:?}",
    );

    // Step 2: refresh fires on the deny. dynamic_ips now contains
    // the cached IP.
    maybe_refresh_dynamic_allowlist_on_deny(&policy, &v1);
    let dynamic_now: HashSet<IpAddr> = policy.dynamic_ips.read().unwrap().clone();
    assert!(
        dynamic_now.contains(&"203.0.113.42".parse().unwrap()),
        "dynamic_ips not populated after refresh: {dynamic_now:?}",
    );

    // Step 3: re-classify the same address. Now allowed.
    let v2 = classify_connect_addr(42, &addr, 16, &policy);
    assert!(
        matches!(v2, Verdict::Allow),
        "expected allow after refresh, got {v2:?}",
    );
}

#[test]
fn dynamic_allowlist_refresh_skips_when_verdict_is_allow() {
    // Sanity: refresh must be a no-op on Allow. Otherwise we'd be
    // hitting DNS on every successful connect.
    use can_net::dns_cache::DnsCache;
    use std::time::Duration;

    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = true;
    policy.allowed_domains = vec!["something.test".to_string()];
    policy.dns_cache = Some(DnsCache::new(Duration::from_secs(60)));

    maybe_refresh_dynamic_allowlist_on_deny(&policy, &Verdict::Allow);
    assert!(
        policy.dynamic_ips.read().unwrap().is_empty(),
        "dynamic_ips should not be touched on Allow",
    );
}

#[test]
fn dynamic_allowlist_refresh_noop_without_cache() {
    // Edge case: policy with allowed_domains but no dns_cache
    // (recipe layer hasn't populated one). Refresh must not panic.
    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = true;
    policy.allowed_domains = vec!["x.test".to_string()];
    policy.dns_cache = None;

    let denied = Verdict::Deny(libc::EACCES as u32);
    maybe_refresh_dynamic_allowlist_on_deny(&policy, &denied);
    assert!(policy.dynamic_ips.read().unwrap().is_empty());
}

#[test]
fn dynamic_allowlist_replaced_atomically_on_each_refresh() {
    // Each refresh REPLACES dynamic_ips with the current union of
    // all allowed domains' cache entries — not appends. This pins
    // the semantics: a domain that fell out of the cache (TTL
    // expired) stops being in dynamic_ips.
    use can_net::dns_cache::DnsCache;
    use std::collections::HashSet;
    use std::time::Duration;

    let mut policy = NotifierPolicy::default();
    policy.restrict_outbound = true;
    policy.allowed_domains = vec!["a.test".to_string(), "b.test".to_string()];
    let cache = DnsCache::new(Duration::from_secs(60));
    let mut a_ips = HashSet::new();
    a_ips.insert("1.1.1.1".parse().unwrap());
    let mut b_ips = HashSet::new();
    b_ips.insert("2.2.2.2".parse().unwrap());
    cache.insert_for_testing("a.test", a_ips, Duration::from_secs(60));
    cache.insert_for_testing("b.test", b_ips, Duration::from_secs(60));
    policy.dns_cache = Some(cache);

    // Pre-populate dynamic_ips with a stale entry. Refresh must
    // overwrite it.
    policy
        .dynamic_ips
        .write()
        .unwrap()
        .insert("9.9.9.9".parse().unwrap());

    maybe_refresh_dynamic_allowlist_on_deny(&policy, &Verdict::Deny(libc::EACCES as u32));

    let after: HashSet<IpAddr> = policy.dynamic_ips.read().unwrap().clone();
    assert!(after.contains(&"1.1.1.1".parse().unwrap()));
    assert!(after.contains(&"2.2.2.2".parse().unwrap()));
    assert!(
        !after.contains(&"9.9.9.9".parse().unwrap()),
        "stale entry should have been replaced, not unioned",
    );
    assert_eq!(after.len(), 2);
}

#[test]
fn socket_sock_type_with_flags_masked_correctly() {
    // The kernel encodes SOCK_NONBLOCK (0x800) and SOCK_CLOEXEC
    // (0x80000) into the sock_type argument. SOCK_TYPE_MASK = 0x0F.
    // SOCK_STREAM=1 → 1 | SOCK_CLOEXEC stays SOCK_STREAM after mask.
    // The SOCK_RAW check must still fire even with these flags set.
    let policy = NotifierPolicy::default();

    // SOCK_STREAM | SOCK_CLOEXEC → still allowed
    let stream_with_cloexec = (libc::SOCK_STREAM as u64) | 0x0008_0000;
    assert!(matches!(
        evaluate_socket(&sock_args(AF_INET, stream_with_cloexec, 0), 42, &policy),
        Verdict::Allow
    ));

    // SOCK_RAW | SOCK_CLOEXEC → still denied for AF_INET
    let raw_with_cloexec = SOCK_RAW | 0x0008_0000;
    assert!(matches!(
        evaluate_socket(&sock_args(AF_INET, raw_with_cloexec, 0), 42, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn exec_root_prefix_allows_everything_under_root() {
    // Edge case: a prefix of "/" matches everything because every
    // absolute path starts with "/" and has a '/' as the next char.
    // This is intentional — a recipe authoring "/*" essentially
    // disables exec filtering. Documented behaviour; pin it here.
    let p = exec_policy(&[], &[""]);
    assert!(is_exec_path_allowed(Path::new("/anything"), &p));
    assert!(is_exec_path_allowed(Path::new("/etc/shadow"), &p));
}

#[test]
fn sendmsg_no_ancillary_zero_namelen_denied() {
    let policy = policy_restricting_to(&[]);
    // msg_name_ptr != 0 but namelen == 0; caller passed None.
    // restrict_outbound branch checks (2..=128).contains(0) == false
    // and denies.
    assert!(matches!(
        classify_sendmsg(42, 0xdead_beef, 0, 0, None, &policy),
        Verdict::Deny(_)
    ));
}

#[test]
fn sendto_inet6_denied_when_not_in_policy() {
    let policy = policy_restricting_to(&["2001:db8::1"]);
    // 2001:db8::2 — different IP
    let mut ip = [0u8; 16];
    ip[0] = 0x20;
    ip[1] = 0x01;
    ip[2] = 0x0d;
    ip[3] = 0xb8;
    ip[15] = 2;
    let bytes = sockaddr_in6(ip, 443);
    assert!(matches!(
        classify_sendto_addr(42, &bytes, 28, &policy),
        Verdict::Deny(_)
    ));
}
