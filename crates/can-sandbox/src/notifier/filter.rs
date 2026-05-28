//! BPF filter installation for the notifier prelude.
//!
//! This filter is installed *before* the main allow/deny filter: seccomp
//! evaluates filters in reverse install order, so this one runs first,
//! and because `SECCOMP_RET_ERRNO` (0x00050000) outranks both
//! `SECCOMP_RET_USER_NOTIF` (0x7fc00000) and the baseline's
//! `SECCOMP_RET_ALLOW` (0x7fff0000), a hard `ERRNO`/`ENOSYS` verdict here
//! correctly overrides whatever the baseline would have done.
//!
//! Two kinds of decision live here:
//!
//! 1. **Register-decidable gates** — decided entirely from immutable
//!    `seccomp_data` registers, so they are race-free and need no
//!    supervisor:
//!    - `socket(domain, type, protocol)`: deny `SOCK_RAW`; restrict
//!      `AF_NETLINK` to `NETLINK_ROUTE`; gate `AF_UNIX`/`AF_INET`/
//!      `AF_INET6` per policy.
//!    - `clone(flags, …)`: deny any namespace-creating flag.
//!    - `clone3(…)`: return `ENOSYS`. Its flags live behind a pointer, so
//!      BPF cannot inspect them; `ENOSYS` makes glibc/musl fall back to
//!      `clone`, which *is* register-filtered above.
//!    - `execveat(…, flags)`: deny `AT_EMPTY_PATH` (fileless exec).
//!
//! 2. **Memory-dependent syscalls** — still routed to the USER_NOTIF
//!    supervisor (`connect`/`sendto`/`sendmsg` for egress, `execve` and
//!    the path arm of `execveat` for the exec allow-list). These are the
//!    TOCTOU-raceable checks being migrated to structural layers in later
//!    phases; until then the supervisor remains their enforcement point.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use super::abi::{
    AF_INET, AF_INET6, AF_NETLINK, AF_UNIX, NS_FLAGS_MASK, SECCOMP_FILTER_FLAG_NEW_LISTENER,
    SECCOMP_RET_USER_NOTIF, SECCOMP_SET_MODE_FILTER, SOCK_RAW, SOCK_TYPE_MASK,
};
use super::bpf::Asm;
use super::error::NotifierError;

/// Syscalls still routed to the USER_NOTIF supervisor for memory-based
/// argument inspection. `socket`/`clone`/`clone3` are intentionally
/// absent — they are decided in static BPF and never reach the
/// supervisor. `execveat` appears because its *path* arm is still
/// supervised even though its `AT_EMPTY_PATH` flag is BPF-denied.
pub const NOTIFIED_SYSCALLS: &[(&str, i64)] = &[
    ("connect", libc::SYS_connect),
    ("sendto", libc::SYS_sendto),
    ("sendmsg", libc::SYS_sendmsg),
    ("execve", libc::SYS_execve),
    ("execveat", libc::SYS_execveat),
];

/// Policy bits compiled into the static filter at build time. A seccomp
/// filter is fixed once installed, so anything policy-dependent (e.g.
/// whether `AF_UNIX` is permitted) must be baked in here rather than
/// decided at runtime.
#[derive(Debug, Clone, Copy)]
pub struct FilterPolicy {
    /// Allow `AF_UNIX` socket creation.
    pub allow_af_unix: bool,
    /// Allow `AF_INET`/`AF_INET6` socket creation.
    pub allow_af_inet: bool,
}

impl Default for FilterPolicy {
    fn default() -> Self {
        Self {
            allow_af_unix: true,
            allow_af_inet: true,
        }
    }
}

// Byte offsets into `struct seccomp_data` for `BPF_LD|BPF_ABS` loads.
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const OFFSET_ARG0: u32 = 16; // domain (socket) / flags (clone)
const OFFSET_ARG1: u32 = 24; // type (socket)
const OFFSET_ARG2: u32 = 32; // protocol (socket)
const OFFSET_ARG4: u32 = 48; // flags (execveat)

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;

/// `NETLINK_ROUTE` — the only netlink protocol the sandbox permits
/// (used by glibc `getifaddrs`, Go, Node, …).
const NETLINK_ROUTE: u32 = 0;

const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32);
const RET_EACCES: u32 = libc::SECCOMP_RET_ERRNO | (libc::EACCES as u32);
const RET_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | (libc::ENOSYS as u32);

/// Build the notifier prelude for the given policy.
pub fn build_notifier_filter(
    policy: &FilterPolicy,
) -> Result<Vec<libc::sock_filter>, NotifierError> {
    let mut a = Asm::new();

    // Shared return targets.
    let allow = a.label();
    let user_notif = a.label();
    let deny_eperm = a.label();
    let deny_eacces = a.label();
    let enosys = a.label();

    // Clause entry points.
    let arch_ok = a.label();
    let arch_bad = a.label();
    let socket_clause = a.label();
    let clone_clause = a.label();
    let execveat_clause = a.label();

    // --- Architecture guard ---
    // On a foreign arch, defer to the main filter (which kills): ALLOW
    // here just means "not my decision".
    a.ld_abs(OFFSET_ARCH);
    a.jeq(AUDIT_ARCH_NATIVE, arch_ok, arch_bad);
    a.mark(arch_bad);
    a.ja(allow);
    a.mark(arch_ok);

    // --- Dispatch on syscall number ---
    a.ld_abs(OFFSET_NR);
    dispatch(&mut a, libc::SYS_socket, socket_clause);
    dispatch(&mut a, libc::SYS_clone, clone_clause);
    dispatch(&mut a, libc::SYS_clone3, enosys);
    dispatch(&mut a, libc::SYS_execveat, execveat_clause);
    dispatch(&mut a, libc::SYS_connect, user_notif);
    dispatch(&mut a, libc::SYS_sendto, user_notif);
    dispatch(&mut a, libc::SYS_sendmsg, user_notif);
    dispatch(&mut a, libc::SYS_execve, user_notif);
    // Not one of ours — let the main filter decide.
    a.ja(allow);

    // --- socket(domain, type, protocol) ---
    let netlink = a.label();
    let af_unix = a.label();
    let af_inet = a.label();
    a.mark(socket_clause);
    a.ld_abs(OFFSET_ARG0); // domain
    let not_netlink = a.label();
    a.jeq(AF_NETLINK as u32, netlink, not_netlink);
    a.mark(not_netlink);
    // Deny SOCK_RAW for every non-netlink domain (packet injection/sniffing).
    a.ld_abs(OFFSET_ARG1); // type
    a.alu_and(SOCK_TYPE_MASK as u32);
    let not_raw = a.label();
    a.jeq(SOCK_RAW as u32, deny_eperm, not_raw);
    a.mark(not_raw);
    a.ld_abs(OFFSET_ARG0); // domain again (A was clobbered)
    let not_unix = a.label();
    a.jeq(AF_UNIX as u32, af_unix, not_unix);
    a.mark(not_unix);
    let not_inet = a.label();
    a.jeq(AF_INET as u32, af_inet, not_inet);
    a.mark(not_inet);
    let not_inet6 = a.label();
    a.jeq(AF_INET6 as u32, af_inet, not_inet6);
    a.mark(not_inet6);
    a.ja(deny_eperm); // unknown domain

    // AF_NETLINK: permit only NETLINK_ROUTE.
    a.mark(netlink);
    a.ld_abs(OFFSET_ARG2); // protocol
    a.jeq(NETLINK_ROUTE, allow, deny_eperm);

    // AF_UNIX / AF_INET(6) gates, compiled from policy.
    a.mark(af_unix);
    a.ja(if policy.allow_af_unix {
        allow
    } else {
        deny_eperm
    });
    a.mark(af_inet);
    a.ja(if policy.allow_af_inet {
        allow
    } else {
        deny_eacces
    });

    // --- clone(flags, …) — deny any namespace-creating flag ---
    // All NS flags fit in the low 32 bits, so the low dword suffices.
    a.mark(clone_clause);
    a.ld_abs(OFFSET_ARG0);
    a.jset(NS_FLAGS_MASK as u32, deny_eperm, allow);

    // --- execveat(…, flags) — deny AT_EMPTY_PATH, else supervise path ---
    a.mark(execveat_clause);
    a.ld_abs(OFFSET_ARG4);
    a.jset(libc::AT_EMPTY_PATH as u32, deny_eacces, user_notif);

    // --- Return blocks ---
    a.mark(allow);
    a.ret(RET_ALLOW);
    a.mark(user_notif);
    a.ret(SECCOMP_RET_USER_NOTIF);
    a.mark(deny_eperm);
    a.ret(RET_EPERM);
    a.mark(deny_eacces);
    a.ret(RET_EACCES);
    a.mark(enosys);
    a.ret(RET_ENOSYS);

    a.build()
}

/// Emit `if nr == syscall goto clause` with a fall-through to the next
/// dispatch check.
fn dispatch(a: &mut Asm, syscall: i64, clause: super::bpf::Label) {
    let next = a.label();
    a.jeq(syscall as u32, clause, next);
    a.mark(next);
}

/// Install the notifier prelude and return the notification fd.
///
/// Must be called from the worker after `PR_SET_NO_NEW_PRIVS` is set. The
/// returned fd is the listener end — send it to the supervisor via the fd
/// channel before `exec()`.
pub fn install_notifier_filter(policy: &FilterPolicy) -> Result<OwnedFd, NotifierError> {
    // PR_SET_NO_NEW_PRIVS is required for unprivileged seccomp.
    // Idempotent — safe even if already set by the main seccomp filter.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(NotifierError::SeccompSyscall(
            std::io::Error::last_os_error(),
        ));
    }

    let filter = build_notifier_filter(policy)?;
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };

    if ret < 0 {
        return Err(NotifierError::SeccompSyscall(
            std::io::Error::last_os_error(),
        ));
    }

    let fd = unsafe { OwnedFd::from_raw_fd(ret as RawFd) };
    tracing::debug!(fd = ret, "installed USER_NOTIF filter, got notifier fd");
    Ok(fd)
}
