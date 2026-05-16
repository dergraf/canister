//! SECCOMP_RET_USER_NOTIF supervisor for argument-level syscall filtering.
//!
//! When the kernel encounters a syscall matching a USER_NOTIF filter, it
//! suspends the calling thread and sends a notification to a supervisor
//! (this module) via a file descriptor. The supervisor reads the syscall
//! arguments, inspects them (e.g., reading memory from `/proc/<pid>/mem`),
//! and sends a verdict (allow or deny).
//!
//! # Architecture
//!
//! The supervisor runs as PID 1 inside the sandbox's PID namespace, not as
//! a thread in the parent. This is necessary because:
//!
//! 1. After `unshare(CLONE_NEWPID)`, `clone(CLONE_THREAD)` returns EINVAL
//!    (pid_ns_for_children != task_active_pid_ns), so we cannot spawn a
//!    supervisor thread.
//! 2. The host's procfs (`s_user_ns = init_user_ns`) denies `/proc/<pid>/mem`
//!    opens from a child user namespace, so the supervisor must mount its own
//!    procfs in the sandbox's user/PID namespace.
//! 3. PID 1 is an ancestor of all sandboxed processes, satisfying Yama
//!    `ptrace_scope=1` without `PR_SET_PTRACER`.
//!
//! ```text
//!   PID 1 (supervisor)                   PID 2+ (worker / sandboxed)
//!   ──────────────────                   ────────────────────────────
//!   1. unshare(CLONE_NEWNS)              1. Sandbox setup (overlay, pivot_root)
//!   2. mount /proc (owned by user ns)    2. Install USER_NOTIF filter
//!   3. Receive notifier fd via           3. Send notifier fd to PID 1
//!      SCM_RIGHTS from worker               via SCM_RIGHTS
//!   4. Loop: poll(notifier_fd, 200ms)    4. exec target command
//!            read notification
//!            inspect via /proc/<pid>/mem
//!            send ALLOW or DENY verdict
//!            waitpid(WNOHANG) for child
//! ```
//!
//! # Memory access
//!
//! The supervisor reads the worker's memory by opening `/proc/<pid>/mem`.
//! Because the supervisor (PID 1) runs in the same user namespace and PID
//! namespace as the sandboxed processes, and mounts its own procfs owned by
//! that user namespace, the kernel's `ptrace_may_access()` check succeeds.
//! As PID 1, the supervisor is an ancestor of all sandboxed processes,
//! satisfying Yama `ptrace_scope=1` automatically.
//!
//! # Requirements
//!
//! - Linux 5.9+ (for `SECCOMP_IOCTL_NOTIF_RECV`, `SECCOMP_IOCTL_NOTIF_SEND`,
//!   `SECCOMP_ADDFD_FLAG_SEND`)
//! - `PR_SET_NO_NEW_PRIVS` must be set on the worker (already done by the
//!   regular filter). The supervisor must NOT have `PR_SET_NO_NEW_PRIVS` set,
//!   as it would break `/proc/<pid>/mem` access.
//!
//! # Filtered syscalls
//!
//! - `connect()` — check destination address against IP allowlist; when an
//!   IP is about to be denied and domain-based filtering is active,
//!   re-resolves all allowed domains to handle TCP DNS and other
//!   resolution paths that bypass sendto/sendmsg interception
//! - `sendto()` / `sendmsg()` — check destination address; UDP DNS queries
//!   (port 53) are inspected at the payload level and trigger
//!   supervisor-side resolution to proactively learn allowed IPs
//! - `clone()` / `clone3()` — deny namespace-creating flags
//! - `socket()` — allow `AF_NETLINK` only for `NETLINK_ROUTE` (protocol 0), deny `SOCK_RAW` for other domains
//! - `execve()` / `execveat()` — validate executable path

use std::collections::HashSet;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use can_policy::config::EgressMode;

use crate::seccomp::SeccompError;

// ---------------------------------------------------------------------------
// Kernel ABI constants (not yet in libc crate for all targets)
// ---------------------------------------------------------------------------

/// `seccomp(SECCOMP_SET_MODE_FILTER, flags, args)` syscall operation.
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;

/// Flag: return a notification fd from `seccomp()`.
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;

/// `SECCOMP_RET_USER_NOTIF` — suspend syscall and notify supervisor.
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

// ioctl numbers for the seccomp notification fd.
// These are architecture-independent on Linux.
//
// SECCOMP_IOCTL_NOTIF_RECV:  _IOWR('!', 0, struct seccomp_notif)
// SECCOMP_IOCTL_NOTIF_SEND:  _IOWR('!', 1, struct seccomp_notif_resp)
// SECCOMP_IOCTL_NOTIF_ID_VALID: _IOW('!', 2, __u64)
//
// On x86_64 (and aarch64 with the same ioctl encoding):
//   _IOWR('!', 0, seccomp_notif)  where sizeof(seccomp_notif)=80 → 0xC0502100
//   _IOWR('!', 1, seccomp_notif_resp) where sizeof=24 → 0xC0182101
//   _IOW('!', 2, u64) where sizeof=8 → 0x40082102
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;

// Clone flag constants for filtering.
const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;
const CLONE_NEWTIME: u64 = 0x0000_0080;

/// All namespace-creating flags that sandboxed processes must not use.
const NS_FLAGS_MASK: u64 = CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWTIME;

// Socket domain/type constants.
const AF_INET: u64 = libc::AF_INET as u64;
const AF_INET6: u64 = libc::AF_INET6 as u64;
const AF_UNIX: u64 = libc::AF_UNIX as u64;
const AF_NETLINK: u64 = libc::AF_NETLINK as u64;
const SOCK_RAW: u64 = libc::SOCK_RAW as u64;

// Mask out SOCK_NONBLOCK and SOCK_CLOEXEC from the type argument.
const SOCK_TYPE_MASK: u64 = 0x0F;

// ---------------------------------------------------------------------------
// Kernel structures (repr(C) for ioctl)
// ---------------------------------------------------------------------------

/// Mirrors `struct seccomp_notif` from <linux/seccomp.h>.
///
/// This is what we receive from `SECCOMP_IOCTL_NOTIF_RECV`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

/// Mirrors `struct seccomp_data` from <linux/seccomp.h>.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

/// Mirrors `struct seccomp_notif_resp` from <linux/seccomp.h>.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

/// Flag for `seccomp_notif_resp.flags`: allow the syscall to proceed.
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// Ensure structs match kernel expectations.
const _: () = {
    assert!(std::mem::size_of::<SeccompNotif>() == 80);
    assert!(std::mem::size_of::<SeccompNotifResp>() == 24);
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Errors from the notifier subsystem.
#[derive(Debug, thiserror::Error)]
pub enum NotifierError {
    #[error("seccomp() syscall failed: {0}")]
    SeccompSyscall(std::io::Error),

    #[error("failed to create unix socket pair: {0}")]
    SocketPair(std::io::Error),

    #[error("failed to send notifier fd via SCM_RIGHTS: {0}")]
    SendFd(std::io::Error),

    #[error("failed to receive notifier fd via SCM_RIGHTS: {0}")]
    RecvFd(std::io::Error),

    #[error("SECCOMP_IOCTL_NOTIF_RECV failed: {0}")]
    NotifRecv(std::io::Error),

    #[error("SECCOMP_IOCTL_NOTIF_SEND failed: {0}")]
    NotifSend(std::io::Error),

    #[error("notifier not supported (requires Linux 5.9+)")]
    NotSupported,

    #[error("failed to read process memory: {0}")]
    ProcMem(std::io::Error),

    #[error("seccomp filter error: {0}")]
    Filter(#[from] SeccompError),
}

/// Policy for the supervisor to enforce.
#[derive(Debug, Clone)]
pub struct NotifierPolicy {
    /// Allowed destination IP addresses for connect()/sendto()/sendmsg().
    pub allowed_ips: HashSet<IpAddr>,

    /// Allowed destination CIDR ranges (stored as (network, prefix_len)).
    pub allowed_cidrs: Vec<(IpAddr, u8)>,

    /// Allowed executable paths for execve()/execveat() — exact matches.
    pub allowed_exec_paths: HashSet<PathBuf>,

    /// Allowed executable path prefixes for execve()/execveat().
    /// Entries from `allow_execve` that end in `/*` are stored here
    /// as the prefix (without the trailing `/*`). A path matches if
    /// it starts with the prefix followed by `/`.
    pub allowed_exec_prefixes: Vec<PathBuf>,

    /// Whether to allow AF_UNIX sockets.
    pub allow_af_unix: bool,

    /// Whether to allow AF_INET / AF_INET6 sockets.
    pub allow_af_inet: bool,

    /// Whether to restrict outbound IP connections.
    ///
    /// When `true`, outbound `connect()`/`sendto()`/`sendmsg()` to
    /// AF_INET/AF_INET6 destinations are checked against `allowed_ips`,
    /// `allowed_cidrs`, `allowed_domains`, and the dynamic allowlist.
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

    /// Whether outbound INET/INET6 traffic must go through local proxy.
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

// ---------------------------------------------------------------------------
// Kernel version detection
// ---------------------------------------------------------------------------

/// Check whether the running kernel supports SECCOMP_RET_USER_NOTIF.
///
/// Requires Linux 5.0 for the basic notification mechanism and Linux 5.9
/// for `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (needed to allow syscalls).
pub fn is_notifier_supported() -> bool {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return false;
    }

    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) };
    let release_str = release.to_string_lossy();

    parse_kernel_version(&release_str)
        .map(|(major, minor)| (major, minor) >= (5, 9))
        .unwrap_or(false)
}

/// Parse "major.minor.patch-extra" into (major, minor).
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

// ---------------------------------------------------------------------------
// Syscall list for USER_NOTIF
// ---------------------------------------------------------------------------

/// Syscalls that the notifier filter intercepts (returns USER_NOTIF for).
pub const NOTIFIED_SYSCALLS: &[(&str, i64)] = &[
    ("connect", libc::SYS_connect),
    ("sendto", libc::SYS_sendto),
    ("sendmsg", libc::SYS_sendmsg),
    ("clone", libc::SYS_clone),
    ("clone3", libc::SYS_clone3),
    ("socket", libc::SYS_socket),
    ("execve", libc::SYS_execve),
    ("execveat", libc::SYS_execveat),
];

// ---------------------------------------------------------------------------
// BPF filter for USER_NOTIF
// ---------------------------------------------------------------------------

/// Build a BPF filter that returns `SECCOMP_RET_USER_NOTIF` for the
/// specified syscalls and `SECCOMP_RET_ALLOW` for everything else.
///
/// This filter is installed *before* the main allow/deny filter.
/// Seccomp evaluates filters in reverse install order — the last-installed
/// filter runs first. The main filter should be installed first, then this
/// one, so this one runs first. If a syscall matches USER_NOTIF here,
/// the main filter is never consulted for that syscall.
pub fn build_notifier_filter() -> Vec<libc::sock_filter> {
    let syscall_nrs: Vec<i64> = NOTIFIED_SYSCALLS.iter().map(|(_, nr)| *nr).collect();

    // Offset of `arch` and `nr` fields in `struct seccomp_data`.
    const OFFSET_ARCH: u32 = 4;
    const OFFSET_NR: u32 = 0;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;

    let mut filter: Vec<libc::sock_filter> = vec![
        // [0] Load architecture
        bpf_stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            OFFSET_ARCH,
        ),
        // [1] Check arch
        bpf_jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            AUDIT_ARCH_NATIVE,
            1,
            0,
        ),
        // [2] Wrong arch → ALLOW (let the main filter handle it)
        bpf_stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_ALLOW,
        ),
        // [3] Load syscall number
        bpf_stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            OFFSET_NR,
        ),
    ];

    // For each notified syscall: if nr matches → jump to USER_NOTIF return.
    for (i, &nr) in syscall_nrs.iter().enumerate() {
        let remaining = (syscall_nrs.len() - 1 - i) as u8;
        filter.push(bpf_jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            nr as u32,
            remaining + 1, // jt: skip remaining + ALLOW → land on USER_NOTIF
            0,             // jf: fall through
        ));
    }

    // Default: ALLOW (not a notified syscall — let through to the main filter).
    filter.push(bpf_stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        libc::SECCOMP_RET_ALLOW,
    ));

    // USER_NOTIF return for matched syscalls.
    filter.push(bpf_stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        SECCOMP_RET_USER_NOTIF,
    ));

    filter
}

// BPF instruction helpers (same as seccomp.rs but private to this module).
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

// ---------------------------------------------------------------------------
// Filter installation (child side)
// ---------------------------------------------------------------------------

/// Install the USER_NOTIF filter and return the notification fd.
///
/// This must be called from the child process after `PR_SET_NO_NEW_PRIVS`
/// is set. The returned fd is the "listener" end — send it to the parent
/// via SCM_RIGHTS.
///
/// # Safety
///
/// The returned fd must be sent to the supervisor before `exec()`. After
/// exec, the fd is closed and the supervisor receives notifications.
pub fn install_notifier_filter() -> Result<OwnedFd, NotifierError> {
    // PR_SET_NO_NEW_PRIVS is required for unprivileged seccomp.
    // This is idempotent — safe to call even if already set by the main
    // seccomp filter path.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(NotifierError::SeccompSyscall(
            std::io::Error::last_os_error(),
        ));
    }

    let filter = build_notifier_filter();
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

    // The return value is the notification fd.
    let fd = unsafe { OwnedFd::from_raw_fd(ret as RawFd) };
    tracing::debug!(fd = ret, "installed USER_NOTIF filter, got notifier fd");
    Ok(fd)
}

// ---------------------------------------------------------------------------
// Fd passing via pipe + pidfd_getfd (avoids sendmsg deadlock)
// ---------------------------------------------------------------------------
//
// The worker's seccomp notifier filter intercepts `sendmsg`, so we cannot
// use SCM_RIGHTS to pass the notifier fd from worker to supervisor — doing
// so would deadlock (the supervisor needs the notifier fd to process the
// very `sendmsg` notification that's trying to send it).
//
// Instead, the worker writes the raw fd number over a pipe using `write()`
// (not intercepted), and the supervisor uses `pidfd_open()` + `pidfd_getfd()`
// (Linux 5.6+) to duplicate the fd from the worker's fd table.

/// Create a pipe for passing the notifier fd number from worker to supervisor.
///
/// Returns `(read_end, write_end)`.
pub fn create_fd_channel() -> Result<(OwnedFd, OwnedFd), NotifierError> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(NotifierError::SocketPair(std::io::Error::last_os_error()));
    }
    let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((read_end, write_end))
}

/// Send the notifier fd number to the supervisor via a pipe.
///
/// The worker writes its raw fd number (as a little-endian i32) using
/// `write()`, which is NOT intercepted by the seccomp notifier filter.
pub fn send_fd(pipe_write: &OwnedFd, fd_to_send: &OwnedFd) -> Result<(), NotifierError> {
    let fd_num = fd_to_send.as_raw_fd();
    let bytes = fd_num.to_le_bytes();
    let ret = unsafe {
        libc::write(
            pipe_write.as_raw_fd(),
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
        )
    };
    if ret < 0 {
        return Err(NotifierError::SendFd(std::io::Error::last_os_error()));
    }
    if (ret as usize) != bytes.len() {
        return Err(NotifierError::SendFd(std::io::Error::other(
            "short write on fd channel pipe",
        )));
    }
    tracing::debug!(fd = fd_num, "sent notifier fd number via pipe");
    Ok(())
}

/// Receive the notifier fd from the worker via pipe + `pidfd_getfd()`.
///
/// Reads the raw fd number from the pipe, then uses `pidfd_open()` +
/// `pidfd_getfd()` to duplicate the fd from the worker's fd table into
/// the supervisor's. This avoids `sendmsg`/SCM_RIGHTS which would be
/// intercepted by the seccomp notifier filter.
pub fn recv_fd(pipe_read: &OwnedFd, worker_pid: i32) -> Result<OwnedFd, NotifierError> {
    let mut buf = [0u8; 4];
    let ret = unsafe {
        libc::read(
            pipe_read.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if ret < 0 {
        return Err(NotifierError::RecvFd(std::io::Error::last_os_error()));
    }
    if (ret as usize) != buf.len() {
        return Err(NotifierError::RecvFd(std::io::Error::other(format!(
            "short read on fd channel pipe ({ret} bytes)",
        ))));
    }
    let target_fd = i32::from_le_bytes(buf);
    tracing::debug!(
        target_fd,
        worker_pid,
        "received notifier fd number, using pidfd_getfd to duplicate"
    );

    // pidfd_open(pid, flags) → pidfd
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, worker_pid, 0i32) };
    if pidfd < 0 {
        return Err(NotifierError::RecvFd(std::io::Error::other(format!(
            "pidfd_open({worker_pid}) failed: {}",
            std::io::Error::last_os_error()
        ))));
    }
    let pidfd = pidfd as i32;

    // pidfd_getfd(pidfd, targetfd, flags) → new fd
    let new_fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, target_fd, 0u32) };
    // Close the pidfd immediately — we only needed it for getfd.
    unsafe { libc::close(pidfd) };

    if new_fd < 0 {
        return Err(NotifierError::RecvFd(std::io::Error::other(format!(
            "pidfd_getfd(pidfd, {target_fd}) failed: {}",
            std::io::Error::last_os_error()
        ))));
    }

    let owned = unsafe { OwnedFd::from_raw_fd(new_fd as i32) };
    tracing::debug!(
        notifier_fd = owned.as_raw_fd(),
        "obtained notifier fd via pidfd_getfd"
    );
    Ok(owned)
}

// ---------------------------------------------------------------------------
// Inline supervisor (single-threaded, runs as PID 1)
// ---------------------------------------------------------------------------

/// Run the seccomp supervisor inline (single-threaded) while monitoring
/// Flag set by the SIGTERM/SIGINT handler to request supervisor shutdown.
/// PID 1 in a PID namespace silently ignores signals without handlers,
/// so we must install an explicit handler.
static SUPERVISOR_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Signal handler for the supervisor (PID 1). Sets the shutdown flag
/// so the poll loop can break out and kill the worker.
extern "C" fn supervisor_signal_handler(_sig: libc::c_int) {
    SUPERVISOR_SHUTDOWN.store(true, Ordering::Release);
}

/// Install signal handlers for SIGTERM and SIGINT in the supervisor.
fn install_supervisor_signal_handler() {
    // SAFETY: signal() is safe with a valid handler.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            supervisor_signal_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            supervisor_signal_handler as *const () as libc::sighandler_t,
        );
    }
}

/// Run the seccomp supervisor loop, processing notifications and monitoring
/// the child process.
///
/// After `unshare(CLONE_NEWPID)`, the intermediate process cannot spawn
/// threads (`clone(CLONE_THREAD)` returns `EINVAL` when
/// `pid_ns_for_children != task_active_pid_ns`). This function runs the
/// supervisor loop directly in the calling process, interleaving seccomp
/// notification handling with non-blocking `waitpid` checks on the child.
///
/// Returns the exit code to use for `process::exit()`.
pub fn run_supervisor_with_child(
    notifier_fd: OwnedFd,
    policy: &NotifierPolicy,
    child: nix::unistd::Pid,
) -> i32 {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};

    // Install a SIGTERM handler so PID 1 can be signaled to shut down.
    // PID 1 in a PID namespace silently drops signals without handlers.
    install_supervisor_signal_handler();

    let fd = notifier_fd.as_raw_fd();
    let mut child_exit_code: Option<i32> = None;

    loop {
        // Check if we received a shutdown signal (SIGTERM/SIGINT).
        if SUPERVISOR_SHUTDOWN.load(Ordering::Acquire) {
            tracing::info!("supervisor received shutdown signal, killing worker");
            let _ = nix::sys::signal::kill(child, nix::sys::signal::SIGKILL);
            // Fall through to waitpid to collect the child's exit status.
        }

        // Check if the child has exited (non-blocking).
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => {
                tracing::debug!(code, "inner child exited");
                child_exit_code = Some(code);
                // Drain remaining notifications before exiting.
                drain_notifications(fd, policy);
                break;
            }
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                let code = 128 + signal as i32;
                tracing::debug!(signal = %signal, code, "inner child killed by signal");
                child_exit_code = Some(code);
                drain_notifications(fd, policy);
                break;
            }
            Ok(WaitStatus::StillAlive) => {
                // Child still running — process notifications.
            }
            Ok(_) => {
                // Other status (stopped, continued) — keep going.
            }
            Err(nix::Error::ECHILD) => {
                // No child — it already exited and was reaped.
                tracing::debug!("inner child already reaped");
                child_exit_code = Some(1);
                break;
            }
            Err(nix::Error::EINTR) => {
                // Interrupted by signal — loop back to check shutdown flag.
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "waitpid failed");
                child_exit_code = Some(1);
                break;
            }
        }

        // Wait for the notifier fd to become readable with a 200ms timeout.
        // This gives us periodic opportunities to check child status.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pfd, 1, 200) };
        if poll_ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            tracing::error!(error = %err, "poll on notifier fd failed");
            break;
        }
        if poll_ret == 0 {
            // Timeout — loop back and check child status.
            continue;
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            tracing::debug!(
                revents = pfd.revents,
                "notifier fd closed/error, stopping supervisor"
            );
            break;
        }

        // Process one notification.
        process_one_notification(fd, policy);
    }

    // If we broke out without getting a child status, block-wait for the child.
    let code = child_exit_code.unwrap_or_else(|| match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, code)) => code,
        Ok(WaitStatus::Signaled(_, signal, _)) => 128 + signal as i32,
        _ => 1,
    });

    // Close the notifier fd explicitly (drop handles it, but be clear).
    drop(notifier_fd);
    tracing::debug!(code, "seccomp supervisor exiting");
    code
}

/// Drain any pending notifications after the child has exited.
///
/// There may be notifications in flight from child processes that are
/// still being torn down. Process them briefly to avoid blocking those
/// teardown paths.
fn drain_notifications(fd: RawFd, policy: &NotifierPolicy) {
    for _ in 0..64 {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_ret = unsafe { libc::poll(&mut pfd, 1, 10) };
        if poll_ret <= 0 {
            break;
        }
        if pfd.revents & libc::POLLIN == 0 {
            break;
        }
        process_one_notification(fd, policy);
    }
}

/// Process a single seccomp notification (receive, evaluate, respond).
fn process_one_notification(fd: RawFd, policy: &NotifierPolicy) {
    let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as _, &mut notif as *mut _) };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOENT) => return,
            Some(libc::EBADF) | Some(libc::EINTR) => return,
            _ => {
                tracing::error!(error = %err, "SECCOMP_IOCTL_NOTIF_RECV failed");
                return;
            }
        }
    }

    let verdict = evaluate_syscall(&notif, policy, fd);

    let resp = match verdict {
        Verdict::Allow => SeccompNotifResp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        },
        Verdict::Deny(errno) => SeccompNotifResp {
            id: notif.id,
            val: 0,
            error: -(errno as i32),
            flags: 0,
        },
    };

    let ret = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as _, &resp as *const _) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOENT) => {
                tracing::debug!(id = notif.id, "notification target gone (ENOENT on send)");
            }
            Some(libc::EBADF) => {
                tracing::debug!("notifier fd closed during send");
            }
            _ => {
                tracing::error!(error = %err, "SECCOMP_IOCTL_NOTIF_SEND failed");
            }
        }
    }
}

/// Verdict from evaluating a syscall notification.
#[derive(Debug)]
enum Verdict {
    /// Allow the syscall to proceed.
    Allow,
    /// Deny the syscall with the given errno.
    Deny(u32),
}

/// Evaluate a syscall notification against the policy.
fn evaluate_syscall(notif: &SeccompNotif, policy: &NotifierPolicy, notifier_fd: RawFd) -> Verdict {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;
    let pid = notif.pid;

    if nr == libc::SYS_connect {
        evaluate_connect(notif, policy, notifier_fd)
    } else if nr == libc::SYS_sendto {
        evaluate_sendto(notif, policy, notifier_fd)
    } else if nr == libc::SYS_sendmsg {
        evaluate_sendmsg(notif, policy, notifier_fd)
    } else if nr == libc::SYS_clone {
        evaluate_clone(args, pid)
    } else if nr == libc::SYS_clone3 {
        evaluate_clone3(notif, notifier_fd)
    } else if nr == libc::SYS_socket {
        evaluate_socket(args, pid, policy)
    } else if nr == libc::SYS_execve {
        evaluate_execve(notif, policy, notifier_fd)
    } else if nr == libc::SYS_execveat {
        evaluate_execveat(notif, policy, notifier_fd)
    } else {
        tracing::warn!(nr, pid, "unexpected syscall in notifier, denying");
        Verdict::Deny(libc::EPERM as u32)
    }
}

// ---------------------------------------------------------------------------
// Notification ID validation (TOCTOU protection)
// ---------------------------------------------------------------------------

/// Check that the notification is still valid (the process hasn't been
/// rescheduled or exited since we read the notification).
///
/// This is critical for TOCTOU safety: between reading the notification
/// and inspecting /proc/<pid>/mem, the process could have been preempted
/// and another thread could have modified the memory. By checking validity
/// after reading memory, we ensure the data is still associated with the
/// suspended syscall.
fn is_notif_id_valid(notifier_fd: RawFd, id: u64) -> bool {
    let ret = unsafe {
        libc::ioctl(
            notifier_fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID as _,
            &id as *const _,
        )
    };
    ret == 0
}

// ---------------------------------------------------------------------------
// Child memory reading (via /proc/<pid>/mem)
// ---------------------------------------------------------------------------

/// Maximum bytes we'll read from a target process's memory in a single call.
/// Largest legitimate read is a pathname (PATH_MAX = 4096).
const MAX_PROC_MEM_READ: usize = 4096;

/// Boundary above which userspace addresses are invalid on x86_64.
/// Kernel virtual addresses start at 0xffff_8000_0000_0000.
const KERNEL_ADDR_BOUNDARY: u64 = 0xffff_8000_0000_0000;

/// Read `len` bytes from `offset` in a child process's memory.
///
/// Opens `/proc/<pid>/mem` for the specific PID on each call. This works
/// because the supervisor runs as PID 1 in the same user namespace and PID
/// namespace as the sandboxed processes, with its own procfs mount. As an
/// ancestor process, Yama `ptrace_scope=1` is satisfied automatically.
fn read_proc_mem(pid: u32, offset: u64, len: usize) -> Result<Vec<u8>, NotifierError> {
    // Reject invalid PID.
    if pid == 0 {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pid is 0",
        )));
    }

    // Reject zero-length or oversized reads.
    if len == 0 || len > MAX_PROC_MEM_READ {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("read length {len} out of bounds (max {MAX_PROC_MEM_READ})"),
        )));
    }

    // Reject kernel-space addresses.
    if offset >= KERNEL_ADDR_BOUNDARY {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("address {offset:#x} is in kernel space"),
        )));
    }

    // Also reject if offset + len would wrap or cross into kernel space.
    if offset
        .checked_add(len as u64)
        .is_none_or(|end| end > KERNEL_ADDR_BOUNDARY)
    {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("read at {offset:#x}+{len} would cross kernel boundary"),
        )));
    }

    // Open /proc/<pid>/mem for this specific process.
    let mem_path = format!("/proc/{pid}/mem");
    let mut file = match std::fs::File::open(&mem_path) {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!(pid, path = %mem_path, error = %e, "failed to open proc mem");
            return Err(NotifierError::ProcMem(e));
        }
    };

    // Seek to the target offset and read.
    use std::io::Seek;
    file.seek(std::io::SeekFrom::Start(offset))
        .map_err(NotifierError::ProcMem)?;

    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).map_err(NotifierError::ProcMem)?;

    Ok(buf)
}

/// Read a NUL-terminated string from a child process's memory.
fn read_proc_string(pid: u32, addr: u64, max_len: usize) -> Result<String, NotifierError> {
    let buf = read_proc_mem(pid, addr, max_len)?;
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Read a NUL-terminated string from a child process's memory, with a
/// `process_vm_readv` fallback and a backoff retry for `/proc/<pid>/mem`.
///
/// On some kernels (e.g. Ubuntu noble cloud kernels), `/proc/<pid>/mem`
/// returns EIO when the worker is paused mid-`execve()` — the mm is in a
/// transient state between the old and new program. `process_vm_readv`
/// is implemented through a different kernel path (no per-fd mm-access
/// check at open time) and frequently succeeds in this window. If both
/// fail, retry the proc/mem read with backoff to give the kernel time to
/// either commit the new mm or roll back. Used only for execve/execveat.
fn read_proc_string_with_retry(
    pid: u32,
    addr: u64,
    max_len: usize,
) -> Result<String, NotifierError> {
    // Fast path 1: try process_vm_readv. Works on most kernels.
    if let Ok(s) = read_proc_string_vm(pid, addr, max_len) {
        return Ok(s);
    }

    // Fast path 2: try /proc/<pid>/mem once without sleeping.
    if let Ok(s) = read_proc_string(pid, addr, max_len) {
        return Ok(s);
    }

    // Slow path: backoff loop alternating both mechanisms.
    const RETRIES: u32 = 12;
    const SLEEP: std::time::Duration = std::time::Duration::from_millis(10);

    let mut last_err = None;
    for _ in 0..RETRIES {
        std::thread::sleep(SLEEP);
        if let Ok(s) = read_proc_string_vm(pid, addr, max_len) {
            return Ok(s);
        }
        match read_proc_string(pid, addr, max_len) {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    // SAFETY-UNWRAP: we only reach this line after the loop executed at
    // least once and every iteration's Err branch sets last_err.
    Err(last_err.expect("loop runs at least once"))
}

/// Read a string from another process's memory via `process_vm_readv(2)`.
///
/// This bypasses the `/proc/<pid>/mem` open + read sequence. The kernel
/// performs the mm-access check at call time rather than at open time,
/// which means it can succeed during the brief window where /proc/mem
/// returns EIO mid-execve.
fn read_proc_string_vm(pid: u32, addr: u64, max_len: usize) -> Result<String, NotifierError> {
    if pid == 0 {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "pid is 0",
        )));
    }
    if max_len == 0 || max_len > MAX_PROC_MEM_READ {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("max_len {max_len} out of bounds"),
        )));
    }
    if addr >= KERNEL_ADDR_BOUNDARY
        || addr
            .checked_add(max_len as u64)
            .is_none_or(|end| end > KERNEL_ADDR_BOUNDARY)
    {
        return Err(NotifierError::ProcMem(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "address in kernel space",
        )));
    }

    let mut buf = vec![0u8; max_len];
    let local_iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: max_len,
    };
    let remote_iov = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: max_len,
    };
    // SAFETY: we pass valid iovecs sized to `max_len`; the kernel writes
    // at most that many bytes into `buf` and returns the count.
    let n = unsafe { libc::process_vm_readv(pid as i32, &local_iov, 1, &remote_iov, 1, 0) };
    if n < 0 {
        return Err(NotifierError::ProcMem(std::io::Error::last_os_error()));
    }
    let n = n as usize;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

// ---------------------------------------------------------------------------
// Syscall evaluators
// ---------------------------------------------------------------------------

/// Evaluate a `connect()` syscall.
///
/// connect(fd, addr, addrlen)
///   args[0] = fd
///   args[1] = pointer to sockaddr
///   args[2] = addrlen
fn evaluate_connect(notif: &SeccompNotif, policy: &NotifierPolicy, notifier_fd: RawFd) -> Verdict {
    let pid = notif.pid;
    let addr_ptr = notif.data.args[1];
    let addr_len = notif.data.args[2] as usize;

    // Validate addr_len.
    if !(2..=128).contains(&addr_len) {
        tracing::warn!(pid, addr_len, "connect: suspicious addr_len, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }

    // Read the sockaddr from the target process.
    let addr_bytes = match read_proc_mem(pid, addr_ptr, addr_len) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "connect: failed to read sockaddr, denying");
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    // Validate the notification is still active (TOCTOU).
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

fn maybe_refresh_dynamic_allowlist_on_deny(policy: &NotifierPolicy, verdict: &Verdict) {
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

/// Classify a connect() destination address and return a verdict.
///
/// This is factored out of `evaluate_connect` so that the address
/// classification logic can be unit-tested with synthetic sockaddr
/// bytes without requiring real `/proc/<pid>/mem` access or seccomp
/// notification fds.
fn classify_connect_addr(
    pid: u32,
    addr_bytes: &[u8],
    addr_len: usize,
    policy: &NotifierPolicy,
) -> Verdict {
    // Parse the address family (first 2 bytes of sockaddr, native endian).
    let sa_family = u16::from_ne_bytes([addr_bytes[0], addr_bytes[1]]);

    // When outbound restrictions are disabled (port-forwarding-only config),
    // allow all IP-family connections without further inspection.
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
            _ => {} // AF_UNIX, AF_UNSPEC, etc. — fall through to normal handling
        }
    }

    if policy.enforce_proxy_egress {
        return classify_proxy_only_connect(pid, addr_bytes, addr_len, sa_family, policy);
    }

    match sa_family as i32 {
        libc::AF_UNSPEC => {
            // AF_UNSPEC is used by connect() to "disconnect" a UDP socket
            // or as part of address probing. This is harmless local operation.
            tracing::debug!(pid, "connect: AF_UNSPEC (disconnect/probe), allowing");
            Verdict::Allow
        }
        libc::AF_UNIX => {
            // AF_UNIX connections are always allowed (local IPC).
            tracing::debug!(pid, "connect: AF_UNIX, allowing");
            Verdict::Allow
        }
        libc::AF_INET => {
            // Parse sockaddr_in: port (bytes 2-3, big-endian), addr (bytes 4-7).
            if addr_len < 8 {
                tracing::warn!(pid, "connect: AF_INET but addr too short");
                return Verdict::Deny(libc::EPERM as u32);
            }
            let port = u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]);
            let ip = Ipv4Addr::new(addr_bytes[4], addr_bytes[5], addr_bytes[6], addr_bytes[7]);
            let ip_addr = IpAddr::V4(ip);

            // Allow unspecified address (0.0.0.0) — used by programs to probe
            // their own network configuration (e.g., Python's http.server,
            // getaddrinfo probing). This is not an outbound connection.
            if ip.is_unspecified() {
                tracing::debug!(pid, port, "connect: IPv4 unspecified (0.0.0.0), allowing");
                return Verdict::Allow;
            }

            // Block multicast (224.0.0.0/4).
            if ip.is_multicast() {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv4 multicast, denying");
                return Verdict::Deny(libc::EACCES as u32);
            }

            // Allow the namespace's DNS server address — needed for DNS
            // resolution inside the sandbox. The sandbox's resolv.conf points here.
            if let Ok(dns_ip) = policy.dns_server_addr.parse::<IpAddr>() {
                if ip_addr == dns_ip {
                    tracing::debug!(pid, %ip_addr, port, "connect: DNS server address, allowing");
                    return Verdict::Allow;
                }
            }

            // Block other link-local (169.254.0.0/16) — often used for cloud
            // metadata services (e.g., AWS 169.254.169.254).
            if ip.is_link_local() {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv4 link-local, denying");
                return Verdict::Deny(libc::EACCES as u32);
            }

            // Block broadcast (255.255.255.255).
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
            // Parse sockaddr_in6: port (bytes 2-3), flowinfo (4-7), addr (bytes 8-23).
            if addr_len < 24 {
                tracing::warn!(pid, "connect: AF_INET6 but addr too short");
                return Verdict::Deny(libc::EPERM as u32);
            }
            let port = u16::from_be_bytes([addr_bytes[2], addr_bytes[3]]);
            let mut addr_buf = [0u8; 16];
            addr_buf.copy_from_slice(&addr_bytes[8..24]);
            let ip = Ipv6Addr::from(addr_buf);
            let ip_addr = IpAddr::V6(ip);

            // Allow unspecified address (::) — used by programs to probe
            // their own network configuration. Not an outbound connection.
            if ip.is_unspecified() {
                tracing::debug!(pid, port, "connect: IPv6 unspecified (::), allowing");
                return Verdict::Allow;
            }

            // Block multicast (ff00::/8).
            if ip.is_multicast() {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv6 multicast, denying");
                return Verdict::Deny(libc::EACCES as u32);
            }

            // Block link-local unicast (fe80::/10).
            // Ipv6Addr doesn't have is_unicast_link_local() on stable,
            // so check the first two bytes directly.
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
            // AF_NETLINK: kernel netlink queries (routing, interfaces).
            // These are read-only kernel information queries, not network access.
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

fn classify_proxy_only_connect(
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

// ---------------------------------------------------------------------------
// sendto / sendmsg evaluators with DNS awareness
// ---------------------------------------------------------------------------

/// DNS port (standard).
/// Minimum valid DNS packet size (header only).
/// Maximum DNS UDP message size we'll inspect.
/// Evaluate a `sendto()` syscall.
///
/// `sendto(fd, buf, len, flags, dest_addr, addrlen)`
///   args[0] = fd
///   args[1] = buf pointer
///   args[2] = len
///   args[3] = flags
///   args[4] = dest_addr pointer
///   args[5] = addrlen
///
/// If `dest_addr` is NULL (args[4] == 0), the socket was previously
/// connected via `connect()` — the destination was already checked then.
/// We allow these "connected UDP send" calls unconditionally.
///
/// For non-NULL dest_addr: if the destination is port 53, parse the DNS
/// query and check the domain against the allowlist. For other ports,
/// check the destination IP against the static + dynamic allowlist.
fn evaluate_sendto(notif: &SeccompNotif, policy: &NotifierPolicy, notifier_fd: RawFd) -> Verdict {
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

/// Classify a sendto() destination address.
///
/// Pure function: takes the raw `sockaddr` bytes and the policy, returns
/// a verdict. No process-state side effects — directly unit-testable
/// with synthetic byte buffers.
///
/// For DNS traffic (port 53), inspects the DNS query payload and checks
/// the domain against the allowlist. For non-DNS traffic, delegates to
/// the same IP classification as connect().
fn classify_sendto_addr(
    pid: u32,
    addr_bytes: &[u8],
    addr_len: usize,
    policy: &NotifierPolicy,
) -> Verdict {
    // Parse address family.
    if addr_len < 2 {
        tracing::warn!(pid, addr_len, "sendto: addr too short, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }
    let sa_family = u16::from_ne_bytes([addr_bytes[0], addr_bytes[1]]);

    // When outbound restrictions are disabled (port-forwarding-only config),
    // allow all IP-family sends without further inspection.
    // Note: we still need to parse DNS traffic for domain filtering if
    // restrict_outbound is true, but when it's false there are no domain
    // rules either, so we can skip everything.
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
            _ => {} // Fall through to normal handling
        }
    }

    // Extract port and IP from the sockaddr.
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
            // Local IPC — always allowed.
            tracing::debug!(pid, "sendto: AF_UNIX, allowing");
            return Verdict::Allow;
        }
        libc::AF_UNSPEC => {
            // Disconnect / probe — harmless.
            tracing::debug!(pid, "sendto: AF_UNSPEC, allowing");
            return Verdict::Allow;
        }
        other => {
            // AF_NETLINK: kernel netlink queries (routing, interfaces).
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
/// `sendmsg(fd, msghdr *msg, flags)`
///   args[0] = fd
///   args[1] = pointer to struct msghdr
///   args[2] = flags
///
/// The destination address is in `msghdr.msg_name` / `msghdr.msg_namelen`.
/// If `msg_name` is NULL, the socket was previously connected — allow.
fn evaluate_sendmsg(notif: &SeccompNotif, policy: &NotifierPolicy, notifier_fd: RawFd) -> Verdict {
    let pid = notif.pid;

    let msghdr_ptr = notif.data.args[1];

    // Read the first 4 fields of struct msghdr (x86_64 layout):
    //   void         *msg_name;       // offset  0, 8 bytes
    //   socklen_t     msg_namelen;     // offset  8, 4 bytes (+4 padding)
    //   struct iovec *msg_iov;         // offset 16, 8 bytes
    //   size_t        msg_iovlen;      // offset 24, 8 bytes
    //   void         *msg_control;     // offset 32, 8 bytes
    //   size_t        msg_controllen;  // offset 40, 8 bytes
    // Total: 48 bytes to reach through msg_controllen.
    let hdr_bytes = match read_proc_mem(pid, msghdr_ptr, 48) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "sendmsg: failed to read msghdr, denying");
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    // SAFETY-UNWRAP: hdr_bytes is sized MSGHDR_SIZE >= 48, and we slice
    // fixed 8-byte / 4-byte windows whose lengths exactly match the target
    // arrays — try_into() cannot fail.
    let msg_name_ptr = u64::from_ne_bytes(hdr_bytes[0..8].try_into().unwrap());
    // SAFETY-UNWRAP: same fixed-window guarantee as msg_name_ptr above.
    let msg_namelen = u32::from_ne_bytes(hdr_bytes[8..12].try_into().unwrap()) as usize;
    // SAFETY-UNWRAP: hdr_bytes is sized MSGHDR_SIZE >= 48; the 8-byte slice
    // length matches u64 exactly.
    let msg_controllen = u64::from_ne_bytes(hdr_bytes[40..48].try_into().unwrap());

    // Read the msg_name bytes once if there's an address to inspect.
    // Used for both the SCM_RIGHTS family check (when msg_controllen > 0)
    // and the outbound destination classification.
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

    // TOCTOU check after all reads but before the verdict commits.
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
/// Defense-in-depth: ancillary data (`msg_controllen > 0`) on non-AF_UNIX
/// sockets is rejected as a belt-and-suspenders guard against SCM_RIGHTS
/// fd injection. The kernel itself rejects SCM_RIGHTS on non-AF_UNIX,
/// but the early reject here gives a clear log line.
///
/// `msg_name_bytes` is `Some(buf)` when the caller successfully read the
/// msg_name buffer (msg_name_ptr != 0 && msg_namelen in 2..=128). When
/// `None`, we treat msg_name as effectively absent.
fn classify_sendmsg(
    pid: u32,
    msg_name_ptr: u64,
    msg_namelen: usize,
    msg_controllen: u64,
    msg_name_bytes: Option<&[u8]>,
    policy: &NotifierPolicy,
) -> Verdict {
    // Ancillary data: SCM_RIGHTS fd-injection guard. Must run BEFORE the
    // restrict_outbound early-return so the inet SCM_RIGHTS case is
    // always rejected regardless of outbound policy.
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

    // When outbound restrictions are disabled, allow without further
    // inspection. Checked AFTER the SCM_RIGHTS block so AF_UNIX/AF_INET
    // distinction still applies.
    if !policy.restrict_outbound {
        tracing::debug!(pid, "sendmsg: outbound unrestricted, allowing");
        return Verdict::Allow;
    }

    // NULL msg_name → connected socket, destination was checked at
    // connect() time.
    if msg_name_ptr == 0 {
        tracing::debug!(pid, "sendmsg: NULL msg_name (connected socket), allowing");
        return Verdict::Allow;
    }

    // Validate msg_namelen bounds.
    if !(2..=128).contains(&msg_namelen) {
        tracing::warn!(pid, msg_namelen, "sendmsg: suspicious msg_namelen, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }

    let Some(addr_bytes) = msg_name_bytes else {
        // Caller signalled "valid msg_name" via the ptr but didn't
        // produce bytes — defensive deny.
        tracing::warn!(pid, "sendmsg: msg_name unreadable, denying");
        return Verdict::Deny(libc::EPERM as u32);
    };

    classify_sendto_addr(pid, addr_bytes, msg_namelen, policy)
}

/// Shared IP classification for outbound traffic (connect, sendto, sendmsg).
///
/// Checks the destination IP against the static policy and dynamic allowlist.
/// Allows loopback, unspecified, and pasta infrastructure addresses.
fn classify_outbound_ip(
    pid: u32,
    ip_addr: IpAddr,
    port: u16,
    policy: &NotifierPolicy,
    syscall_name: &str,
) -> Verdict {
    // Allow loopback.
    if ip_addr.is_loopback() {
        tracing::debug!(pid, %ip_addr, port, "{syscall_name}: loopback, allowing");
        return Verdict::Allow;
    }

    // Allow unspecified.
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

    // Block broadcast.
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

// ---------------------------------------------------------------------------
// DNS query inspection and supervisor-side resolution
// ---------------------------------------------------------------------------

/// Evaluate a `clone()` syscall.
///
/// clone(flags, ...)
///   args[0] = clone flags
fn evaluate_clone(args: &[u64; 6], pid: u32) -> Verdict {
    let flags = args[0];

    let ns_flags = flags & NS_FLAGS_MASK;
    if ns_flags != 0 {
        tracing::warn!(
            pid,
            flags = format!("{:#x}", flags),
            ns_flags = format!("{:#x}", ns_flags),
            "clone: namespace flags denied"
        );
        Verdict::Deny(libc::EPERM as u32)
    } else {
        Verdict::Allow
    }
}

/// Evaluate a `clone3()` syscall.
///
/// clone3(struct clone_args *args, size_t size)
///   args[0] = pointer to struct clone_args
///   args[1] = size
///
/// We need to read the `flags` field from struct clone_args (first u64).
fn evaluate_clone3(notif: &SeccompNotif, notifier_fd: RawFd) -> Verdict {
    let pid = notif.pid;
    let args_ptr = notif.data.args[0];
    let args_size = notif.data.args[1] as usize;

    // struct clone_args { u64 flags; ... }
    // flags is the first field (offset 0, 8 bytes).
    if args_size < 8 {
        tracing::warn!(pid, args_size, "clone3: args too small, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }

    let flags_bytes = match read_proc_mem(pid, args_ptr, 8) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "clone3: failed to read flags, denying");
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    // TOCTOU check.
    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(pid, "clone3: notification invalidated (TOCTOU)");
        return Verdict::Deny(libc::EPERM as u32);
    }

    // SAFETY-UNWRAP: flags_bytes was just read as exactly 8 bytes; the
    // try_into() to [u8; 8] cannot fail.
    let flags = u64::from_ne_bytes(flags_bytes.try_into().unwrap());
    let ns_flags = flags & NS_FLAGS_MASK;
    if ns_flags != 0 {
        tracing::warn!(
            pid,
            flags = format!("{:#x}", flags),
            ns_flags = format!("{:#x}", ns_flags),
            "clone3: namespace flags denied"
        );
        Verdict::Deny(libc::EPERM as u32)
    } else {
        Verdict::Allow
    }
}

/// Evaluate a `socket()` syscall.
///
/// socket(domain, type, protocol)
///   args[0] = domain (AF_INET, AF_UNIX, AF_NETLINK, ...)
///   args[1] = type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, ...)
///   args[2] = protocol
fn evaluate_socket(args: &[u64; 6], pid: u32, policy: &NotifierPolicy) -> Verdict {
    let domain = args[0];
    let sock_type = args[1] & SOCK_TYPE_MASK;

    // AF_NETLINK: only allow NETLINK_ROUTE (protocol 0).
    //
    // Netlink sockets use SOCK_RAW or SOCK_DGRAM (they're equivalent for netlink).
    // Netlink SOCK_RAW is NOT raw packet access — it's the standard way to query
    // routing tables, interface addresses, etc. via the kernel netlink interface.
    // Many programs (glibc's getifaddrs, Go, Bun/Node) use NETLINK_ROUTE.
    //
    // Other netlink protocols are dangerous or leak host information:
    //   NETLINK_AUDIT (9)        — security audit subsystem
    //   NETLINK_KOBJECT_UEVENT (15) — device hotplug events
    //   NETLINK_CONNECTOR (11)   — kernel connector interface
    //   NETLINK_SELINUX (7)      — SELinux event notifications
    //   NETLINK_FIREWALL (3)     — iptables (deprecated)
    //
    // We restrict to NETLINK_ROUTE (0) which covers:
    //   - Interface enumeration (getifaddrs)
    //   - Routing table queries
    //   - Address resolution
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

    // Deny SOCK_RAW for all other domains (AF_INET, AF_INET6, etc.).
    // Raw sockets enable packet injection and sniffing — dangerous in a sandbox.
    if sock_type == SOCK_RAW {
        tracing::warn!(pid, domain, "socket: SOCK_RAW denied");
        return Verdict::Deny(libc::EPERM as u32);
    }

    // Allow AF_UNIX always (local IPC).
    if domain == AF_UNIX {
        if policy.allow_af_unix {
            return Verdict::Allow;
        } else {
            tracing::warn!(pid, "socket: AF_UNIX denied by policy");
            return Verdict::Deny(libc::EPERM as u32);
        }
    }

    // Allow AF_INET / AF_INET6 if permitted by policy.
    if domain == AF_INET || domain == AF_INET6 {
        if policy.allow_af_inet {
            return Verdict::Allow;
        } else {
            tracing::warn!(pid, domain, "socket: AF_INET/6 denied by policy");
            return Verdict::Deny(libc::EACCES as u32);
        }
    }

    // All other domains are denied.
    tracing::warn!(pid, domain, "socket: unknown domain denied");
    Verdict::Deny(libc::EPERM as u32)
}

/// Check if a canonicalized path is allowed by the exec policy.
///
/// Checks exact matches in `allowed_exec_paths` first, then prefix
/// matches in `allowed_exec_prefixes` (entries from `allow_execve`
/// that ended in `/*`). Prefix matching requires a `/` boundary
/// after the prefix to prevent partial directory name matches.
fn is_exec_path_allowed(canonical: &Path, policy: &NotifierPolicy) -> bool {
    // Exact match.
    if policy.allowed_exec_paths.contains(canonical) {
        return true;
    }
    // Prefix match: "/nix/store/*" matches "/nix/store/abc123/bin/mix".
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
/// execve(pathname, argv, envp)
///   args[0] = pointer to pathname string
fn evaluate_execve(notif: &SeccompNotif, policy: &NotifierPolicy, notifier_fd: RawFd) -> Verdict {
    let pid = notif.pid;
    let pathname_ptr = notif.data.args[0];

    // If no exec path restrictions, allow all.
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

    // TOCTOU check.
    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(pid, "execve: notification invalidated (TOCTOU)");
        return Verdict::Deny(libc::EPERM as u32);
    }

    let path = PathBuf::from(&pathname);
    // Canonicalize the path (resolve symlinks) for consistent matching.
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
/// execveat(dirfd, pathname, argv, envp, flags)
///   args[0] = dirfd
///   args[1] = pointer to pathname string
///   args[4] = flags (AT_EMPTY_PATH means use dirfd directly)
fn evaluate_execveat(notif: &SeccompNotif, policy: &NotifierPolicy, notifier_fd: RawFd) -> Verdict {
    let pid = notif.pid;
    let pathname_ptr = notif.data.args[1];
    let flags = notif.data.args[4] as i32;

    // If no exec path restrictions, allow all.
    if policy.allowed_exec_paths.is_empty() && policy.allowed_exec_prefixes.is_empty() {
        return Verdict::Allow;
    }

    // AT_EMPTY_PATH with a pathname pointer of 0 or empty string means
    // "execute the file referred to by dirfd" — this is the fileless
    // execution pattern (memfd_create + execveat). Deny it.
    if flags & libc::AT_EMPTY_PATH != 0 {
        tracing::warn!(
            pid,
            "execveat: AT_EMPTY_PATH used (potential fileless execution), denying"
        );
        return Verdict::Deny(libc::EACCES as u32);
    }

    // Read the pathname.
    let pathname = match read_proc_string_with_retry(pid, pathname_ptr, 4096) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(pid, error = %e, "execveat: failed to read pathname, denying");
            return Verdict::Deny(libc::EACCES as u32);
        }
    };

    // TOCTOU check.
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

// ---------------------------------------------------------------------------
// Helper: IP CIDR matching
// ---------------------------------------------------------------------------

/// Check if an IP address falls within a CIDR range.
fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
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

// ---------------------------------------------------------------------------
// Helper: build policy from config
// ---------------------------------------------------------------------------

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

    // Add pre-resolved IPs from allowed domains.
    for (_domain, ips) in resolved_ips {
        for ip in ips {
            allowed_ips.insert(*ip);
        }
    }

    // Add explicitly allowed IPs and CIDRs.
    for ip_str in &config.network.allow_ips {
        if let Some((net, prefix)) = parse_cidr(ip_str) {
            allowed_cidrs.push((net, prefix));
        } else if let Ok(ip) = ip_str.parse::<IpAddr>() {
            allowed_ips.insert(ip);
        } else {
            tracing::warn!(ip = ip_str, "could not parse allowed IP/CIDR, skipping");
        }
    }

    // DNS server address — always allowed.
    // The namespace's resolv.conf points to this address. The actual DNS
    // filtering happens at the query level (domain allowlist check in
    // evaluate_dns_sendto). We also allow the PASTA_DNS_ADDR fallback
    // in case the detection result is different from the link-local address.
    if let Ok(ip) = dns_addr.parse::<IpAddr>() {
        allowed_ips.insert(ip);
    }
    allowed_ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    allowed_ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    // SAFETY-UNWRAP: PASTA_DNS_ADDR is a const &str whose validity as an
    // IP literal is checked by can_net::pasta tests.
    allowed_ips.insert(can_net::pasta::PASTA_DNS_ADDR.parse().unwrap());

    // Allow the host's default gateway — pasta mirrors the host's
    // network configuration, so the gateway is a real IP that the
    // sandbox needs to reach for outbound traffic.
    if let Some(gw) = can_net::pasta::detect_default_gateway() {
        allowed_ips.insert(IpAddr::V4(gw));
        tracing::debug!(gateway = %gw, "added default gateway to notifier allowlist");
    }

    // Build allowed exec paths from process config.
    // Entries ending in `/*` are treated as prefix rules (match any path
    // under that directory). All others are exact matches.
    let mut allowed_exec_paths: HashSet<PathBuf> = HashSet::new();
    let mut allowed_exec_prefixes: Vec<PathBuf> = Vec::new();

    for p in &config.process.allow_execve {
        let s = p.as_os_str().to_string_lossy();
        if let Some(prefix_str) = s.strip_suffix("/*") {
            // Strip trailing "/*" to get the directory prefix.
            let prefix_path = PathBuf::from(prefix_str);
            // Canonicalize the prefix directory if it exists.
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
    // Restrict when:
    //   * an explicit allow list is configured (domains or IPs); the
    //     supervisor enforces that list, OR
    //   * the egress mode is `proxy-only` or `none`; these modes are
    //     themselves restrictive (proxy-only allows only the local
    //     proxy port; none allows nothing). Without this term,
    //     `egress = "none"` with no allow lists falls through to the
    //     "outbound unrestricted" branch and the supervisor allows
    //     every connect — the exact bypass we're guarding against.
    //
    // Port-forwarding-only `direct` configs (no domains, no IPs, no
    // explicit restriction) intentionally do NOT set this; the notifier
    // is still useful for clone/socket/execve enforcement but allows
    // raw outbound.
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
        // `egress = "none"` and `egress = "proxy-only"` both restrict the
        // worker to a tiny set of addresses; the difference is that
        // proxy-only ALSO whitelists the proxy port. We route both
        // through `classify_proxy_only_connect`, which checks
        // `Some(port) == policy.proxy_port` — when egress is None the
        // proxy isn't started and `proxy_port` is None, so no port
        // matches and everything (except AF_UNIX/AF_UNSPEC) is denied.
        // Without this, `egress = "none"` defaulted to ALLOW-ALL
        // because `restrict_outbound` only fires when allow lists are
        // non-empty.
        enforce_proxy_egress: matches!(egress_mode, EgressMode::ProxyOnly | EgressMode::None),
        proxy_port,
    }
}

/// Parse a CIDR string like "10.0.0.0/8" into (network, prefix_len).
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: IpAddr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    Some((ip, prefix))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
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
}
