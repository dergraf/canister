//! `socket()`, `execve()`, `execveat()` evaluators — the "what kind of
//! resource is this process allowed to use" gates. Distinct from
//! eval_net (which checks per-call destinations) and eval_clone
//! (namespace flags).

use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use super::abi::{AF_INET, AF_INET6, AF_NETLINK, AF_UNIX, SOCK_RAW, SOCK_TYPE_MASK, SeccompNotif};
use super::policy::NotifierPolicy;
use super::proc_mem::read_proc_string_with_retry;
use super::supervisor::{Verdict, is_notif_id_valid};

/// Evaluate a `socket()` syscall.
///
/// `socket(domain, type, protocol)`:
///   args[0] = domain (AF_INET, AF_UNIX, AF_NETLINK, ...)
///   args[1] = type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, ...)
///   args[2] = protocol
pub(super) fn evaluate_socket(args: &[u64; 6], pid: u32, policy: &NotifierPolicy) -> Verdict {
    let domain = args[0];
    let sock_type = args[1] & SOCK_TYPE_MASK;

    // AF_NETLINK: only allow NETLINK_ROUTE (protocol 0).
    //
    // Netlink sockets use SOCK_RAW or SOCK_DGRAM (equivalent for
    // netlink). Netlink SOCK_RAW is NOT raw packet access — it's the
    // standard way to query routing tables, interface addresses, etc.
    // via the kernel netlink interface. Many programs (glibc's
    // getifaddrs, Go, Bun/Node) use NETLINK_ROUTE.
    //
    // Other netlink protocols are dangerous or leak host information:
    //   NETLINK_AUDIT (9)            — security audit subsystem
    //   NETLINK_KOBJECT_UEVENT (15)  — device hotplug events
    //   NETLINK_CONNECTOR (11)       — kernel connector interface
    //   NETLINK_SELINUX (7)          — SELinux event notifications
    //   NETLINK_FIREWALL (3)         — iptables (deprecated)
    if domain == AF_NETLINK {
        let protocol = args[2];
        const NETLINK_ROUTE: u64 = 0;
        if protocol == NETLINK_ROUTE {
            tracing::debug!(
                pid,
                sock_type,
                protocol,
                "socket: AF_NETLINK NETLINK_ROUTE allowed"
            );
            return Verdict::Allow;
        } else {
            tracing::warn!(
                pid,
                sock_type,
                protocol,
                "socket: AF_NETLINK non-ROUTE protocol denied"
            );
            return Verdict::Deny(libc::EPERM as u32);
        }
    }

    // Deny SOCK_RAW for all other domains. Raw sockets enable packet
    // injection and sniffing — dangerous in a sandbox.
    if sock_type == SOCK_RAW {
        tracing::warn!(pid, domain, "socket: SOCK_RAW denied");
        return Verdict::Deny(libc::EPERM as u32);
    }

    if domain == AF_UNIX {
        if policy.allow_af_unix {
            return Verdict::Allow;
        } else {
            tracing::warn!(pid, "socket: AF_UNIX denied by policy");
            return Verdict::Deny(libc::EPERM as u32);
        }
    }

    if domain == AF_INET || domain == AF_INET6 {
        if policy.allow_af_inet {
            return Verdict::Allow;
        } else {
            tracing::warn!(pid, domain, "socket: AF_INET/6 denied by policy");
            return Verdict::Deny(libc::EACCES as u32);
        }
    }

    tracing::warn!(pid, domain, "socket: unknown domain denied");
    Verdict::Deny(libc::EPERM as u32)
}

/// Check if a canonicalised path is allowed by the exec policy.
///
/// Exact matches in `allowed_exec_paths` win first. Otherwise, prefix
/// matches in `allowed_exec_prefixes` (entries from `allow_execve` that
/// ended in `/*`). Prefix matching requires a `/` boundary after the
/// prefix to prevent partial directory name matches.
pub(super) fn is_exec_path_allowed(canonical: &Path, policy: &NotifierPolicy) -> bool {
    if policy.allowed_exec_paths.contains(canonical) {
        return true;
    }
    let canonical_str = canonical.to_string_lossy();
    for prefix in &policy.allowed_exec_prefixes {
        let prefix_str = prefix.to_string_lossy();
        if canonical_str.starts_with(prefix_str.as_ref())
            && canonical_str.as_bytes().get(prefix_str.len()) == Some(&b'/')
        {
            return true;
        }
    }
    false
}

/// Evaluate an `execve()` syscall.
///
/// `execve(pathname, argv, envp)`: `args[0]` = pointer to pathname.
pub(super) fn evaluate_execve(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;
    let pathname_ptr = notif.data.args[0];

    if policy.allowed_exec_paths.is_empty() && policy.allowed_exec_prefixes.is_empty() {
        return Verdict::Allow;
    }

    let pathname = match read_proc_string_with_retry(pid, pathname_ptr, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(pid, error = %e, "execve: failed to read pathname, denying");
            return Verdict::Deny(libc::EACCES as u32);
        }
    };

    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(pid, "execve: notification invalidated (TOCTOU)");
        return Verdict::Deny(libc::EPERM as u32);
    }

    let path = PathBuf::from(&pathname);
    let canonical = path.canonicalize().unwrap_or(path);

    if is_exec_path_allowed(&canonical, policy) {
        tracing::debug!(pid, path = %canonical.display(), "execve: allowed");
        Verdict::Allow
    } else {
        tracing::warn!(pid, path = %canonical.display(), "execve: denied by policy");
        Verdict::Deny(libc::EACCES as u32)
    }
}

/// Evaluate an `execveat()` syscall.
///
/// `execveat(dirfd, pathname, argv, envp, flags)`:
///   args[0] = dirfd
///   args[1] = pointer to pathname
///   args[4] = flags (`AT_EMPTY_PATH` means "use dirfd directly")
pub(super) fn evaluate_execveat(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;
    let pathname_ptr = notif.data.args[1];
    let flags = notif.data.args[4] as i32;

    if policy.allowed_exec_paths.is_empty() && policy.allowed_exec_prefixes.is_empty() {
        return Verdict::Allow;
    }

    // AT_EMPTY_PATH is the fileless-exec pattern (memfd_create +
    // execveat with no real path on disk). Always deny.
    if flags & libc::AT_EMPTY_PATH != 0 {
        tracing::warn!(
            pid,
            "execveat: AT_EMPTY_PATH used (potential fileless execution), denying"
        );
        return Verdict::Deny(libc::EACCES as u32);
    }

    let pathname = match read_proc_string_with_retry(pid, pathname_ptr, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(pid, error = %e, "execveat: failed to read pathname, denying");
            return Verdict::Deny(libc::EACCES as u32);
        }
    };

    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(pid, "execveat: notification invalidated (TOCTOU)");
        return Verdict::Deny(libc::EPERM as u32);
    }

    let path = PathBuf::from(&pathname);
    let canonical = path.canonicalize().unwrap_or(path);

    if is_exec_path_allowed(&canonical, policy) {
        tracing::debug!(pid, path = %canonical.display(), "execveat: allowed");
        Verdict::Allow
    } else {
        tracing::warn!(pid, path = %canonical.display(), "execveat: denied by policy");
        Verdict::Deny(libc::EACCES as u32)
    }
}
