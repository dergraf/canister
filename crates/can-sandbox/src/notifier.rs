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
//! - `connect()` — check destination address against IP allowlist
//! - `sendto()` / `sendmsg()` — check destination address; DNS queries
//!   (port 53) are checked against the domain allowlist and trigger
//!   supervisor-side resolution to dynamically learn allowed IPs
//! - `clone()` / `clone3()` — deny namespace-creating flags
//! - `socket()` — deny `AF_NETLINK`, `SOCK_RAW`
//! - `execve()` / `execveat()` — validate executable path

use std::collections::HashSet;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use can_net::pasta::PASTA_DNS_ADDR;

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

    /// Allowed domain names for DNS queries.
    ///
    /// When a sandboxed process sends a DNS query (sendto/sendmsg to port 53),
    /// the queried domain is checked against this list. Matching uses suffix
    /// semantics: `"example.com"` allows `example.com` and `*.example.com`.
    /// If the domain is allowed, the supervisor resolves it and adds the
    /// resulting IPs to the dynamic allowlist.
    pub allowed_domains: Vec<String>,

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
}

impl Default for NotifierPolicy {
    fn default() -> Self {
        Self {
            allowed_ips: HashSet::new(),
            allowed_cidrs: Vec::new(),
            allowed_domains: Vec::new(),
            allowed_exec_paths: HashSet::new(),
            allowed_exec_prefixes: Vec::new(),
            allow_af_unix: true,
            allow_af_inet: true,
            restrict_outbound: true,
        }
    }
}

/// Thread-safe dynamic IP allowlist.
///
/// When the notifier sees a DNS query for an allowed domain, the supervisor
/// resolves that domain in a background thread and adds the resulting IPs
/// here. The `evaluate_connect` and `evaluate_sendto` functions check this
/// list alongside the static `NotifierPolicy.allowed_ips`.
///
/// Uses `RwLock` for low-contention reads (the common path) with occasional
/// writes from resolver threads.
#[derive(Debug, Clone)]
pub struct DynamicAllowlist {
    ips: Arc<RwLock<HashSet<IpAddr>>>,
}

impl Default for DynamicAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicAllowlist {
    /// Create a new empty dynamic allowlist.
    pub fn new() -> Self {
        Self {
            ips: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Check whether an IP is in the dynamic allowlist.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ips
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(ip)
    }

    /// Add IPs to the dynamic allowlist.
    pub fn add_ips(&self, ips: impl IntoIterator<Item = IpAddr>) {
        let mut set = self.ips.write().unwrap_or_else(|e| e.into_inner());
        set.extend(ips);
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
    dynamic_allowlist: &DynamicAllowlist,
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
                drain_notifications(fd, policy, dynamic_allowlist);
                break;
            }
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                let code = 128 + signal as i32;
                tracing::debug!(signal = %signal, code, "inner child killed by signal");
                child_exit_code = Some(code);
                drain_notifications(fd, policy, dynamic_allowlist);
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
        process_one_notification(fd, policy, dynamic_allowlist);
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
fn drain_notifications(fd: RawFd, policy: &NotifierPolicy, dynamic_allowlist: &DynamicAllowlist) {
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
        process_one_notification(fd, policy, dynamic_allowlist);
    }
}

/// Process a single seccomp notification (receive, evaluate, respond).
fn process_one_notification(
    fd: RawFd,
    policy: &NotifierPolicy,
    dynamic_allowlist: &DynamicAllowlist,
) {
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

    let verdict = evaluate_syscall(&notif, policy, dynamic_allowlist, fd);

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
fn evaluate_syscall(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    dynamic_allowlist: &DynamicAllowlist,
    notifier_fd: RawFd,
) -> Verdict {
    let nr = notif.data.nr as i64;
    let args = &notif.data.args;
    let pid = notif.pid;

    if nr == libc::SYS_connect {
        evaluate_connect(notif, policy, dynamic_allowlist, notifier_fd)
    } else if nr == libc::SYS_sendto {
        evaluate_sendto(notif, policy, dynamic_allowlist, notifier_fd)
    } else if nr == libc::SYS_sendmsg {
        evaluate_sendmsg(notif, policy, dynamic_allowlist, notifier_fd)
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

// ---------------------------------------------------------------------------
// Syscall evaluators
// ---------------------------------------------------------------------------

/// Evaluate a `connect()` syscall.
///
/// connect(fd, addr, addrlen)
///   args[0] = fd
///   args[1] = pointer to sockaddr
///   args[2] = addrlen
fn evaluate_connect(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    dynamic_allowlist: &DynamicAllowlist,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;
    let addr_ptr = notif.data.args[1];
    let addr_len = notif.data.args[2] as usize;

    // Sanity check addr_len.
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

    classify_connect_addr(pid, &addr_bytes, addr_len, policy, dynamic_allowlist)
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
    dynamic_allowlist: &DynamicAllowlist,
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

            // Allow the pasta DNS address (link-local) — needed for DNS resolution
            // inside the sandbox. The sandbox's resolv.conf points here.
            if ip_addr == PASTA_DNS_ADDR.parse::<IpAddr>().unwrap() {
                tracing::debug!(pid, %ip_addr, port, "connect: pasta DNS address, allowing");
                return Verdict::Allow;
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

            if policy.is_ip_allowed(ip_addr) || dynamic_allowlist.contains(&ip_addr) {
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

            if policy.is_ip_allowed(ip_addr) || dynamic_allowlist.contains(&ip_addr) {
                tracing::debug!(pid, %ip_addr, port, "connect: IPv6 allowed");
                Verdict::Allow
            } else {
                tracing::warn!(pid, %ip_addr, port, "connect: IPv6 denied by policy");
                Verdict::Deny(libc::EACCES as u32)
            }
        }
        other => {
            tracing::warn!(
                pid,
                family = other,
                "connect: unknown address family, denying"
            );
            Verdict::Deny(libc::EPERM as u32)
        }
    }
}

// ---------------------------------------------------------------------------
// sendto / sendmsg evaluators with DNS awareness
// ---------------------------------------------------------------------------

/// DNS port (standard).
const DNS_PORT: u16 = 53;

/// Minimum valid DNS packet size (header only).
const DNS_HEADER_SIZE: usize = 12;

/// Maximum DNS UDP message size we'll inspect.
const DNS_MAX_INSPECT: usize = 512;

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
fn evaluate_sendto(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    dynamic_allowlist: &DynamicAllowlist,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;
    let dest_addr_ptr = notif.data.args[4];
    let addr_len = notif.data.args[5] as usize;

    // NULL dest_addr → connected socket, destination was checked at connect() time.
    if dest_addr_ptr == 0 {
        tracing::debug!(pid, "sendto: NULL dest_addr (connected socket), allowing");
        return Verdict::Allow;
    }

    // Sanity check addr_len.
    if !(2..=128).contains(&addr_len) {
        tracing::warn!(pid, addr_len, "sendto: suspicious addr_len, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }

    // Read the sockaddr from the target process.
    let addr_bytes = match read_proc_mem(pid, dest_addr_ptr, addr_len) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "sendto: failed to read sockaddr, denying");
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    // TOCTOU check.
    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(pid, "sendto: notification invalidated (TOCTOU)");
        return Verdict::Deny(libc::EPERM as u32);
    }

    classify_sendto_addr(
        notif,
        &addr_bytes,
        addr_len,
        policy,
        dynamic_allowlist,
        notifier_fd,
    )
}

/// Classify a sendto() destination address.
///
/// For DNS traffic (port 53), inspects the DNS query payload and checks
/// the domain against the allowlist. For non-DNS traffic, delegates to
/// the same IP classification as connect().
fn classify_sendto_addr(
    notif: &SeccompNotif,
    addr_bytes: &[u8],
    addr_len: usize,
    policy: &NotifierPolicy,
    dynamic_allowlist: &DynamicAllowlist,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;

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
            tracing::warn!(
                pid,
                family = other,
                "sendto: unknown address family, denying"
            );
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    // DNS traffic: check domain, trigger resolution.
    if port == DNS_PORT {
        return evaluate_dns_sendto(notif, policy, dynamic_allowlist, &ip_addr, notifier_fd);
    }

    // Non-DNS traffic: check IP against policy (same rules as connect).
    classify_outbound_ip(pid, ip_addr, port, policy, dynamic_allowlist, "sendto")
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
fn evaluate_sendmsg(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    dynamic_allowlist: &DynamicAllowlist,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;

    // When outbound restrictions are disabled (port-forwarding-only config),
    // allow all sendmsg calls without inspecting the destination.
    if !policy.restrict_outbound {
        tracing::debug!(pid, "sendmsg: outbound unrestricted, allowing");
        return Verdict::Allow;
    }

    let msghdr_ptr = notif.data.args[1];

    // Read the first 2 fields of struct msghdr:
    //   void *msg_name;       // 8 bytes on x86_64
    //   socklen_t msg_namelen; // 4 bytes (but aligned to 8 on x86_64)
    // Total: 16 bytes (pointer + padded socklen_t)
    let hdr_bytes = match read_proc_mem(pid, msghdr_ptr, 16) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "sendmsg: failed to read msghdr, denying");
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    let msg_name_ptr = u64::from_ne_bytes(hdr_bytes[0..8].try_into().unwrap());
    let msg_namelen = u32::from_ne_bytes(hdr_bytes[8..12].try_into().unwrap()) as usize;

    // NULL msg_name → connected socket, destination was checked at connect() time.
    if msg_name_ptr == 0 {
        tracing::debug!(pid, "sendmsg: NULL msg_name (connected socket), allowing");
        return Verdict::Allow;
    }

    // Sanity check.
    if !(2..=128).contains(&msg_namelen) {
        tracing::warn!(pid, msg_namelen, "sendmsg: suspicious msg_namelen, denying");
        return Verdict::Deny(libc::EPERM as u32);
    }

    // Read the sockaddr.
    let addr_bytes = match read_proc_mem(pid, msg_name_ptr, msg_namelen) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "sendmsg: failed to read msg_name, denying");
            return Verdict::Deny(libc::EPERM as u32);
        }
    };

    // TOCTOU check.
    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(pid, "sendmsg: notification invalidated (TOCTOU)");
        return Verdict::Deny(libc::EPERM as u32);
    }

    // Reuse the sendto classification logic.
    classify_sendto_addr(
        notif,
        &addr_bytes,
        msg_namelen,
        policy,
        dynamic_allowlist,
        notifier_fd,
    )
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
    dynamic_allowlist: &DynamicAllowlist,
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

    // Allow pasta DNS address.
    if ip_addr == PASTA_DNS_ADDR.parse::<IpAddr>().unwrap() {
        tracing::debug!(pid, %ip_addr, port, "{syscall_name}: pasta DNS address, allowing");
        return Verdict::Allow;
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

    // Check static policy + dynamic allowlist.
    if policy.is_ip_allowed(ip_addr) || dynamic_allowlist.contains(&ip_addr) {
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

/// Evaluate a sendto() that targets port 53 (DNS).
///
/// Reads the DNS query payload from the process's memory, extracts the
/// queried domain name, and checks it against the domain allowlist.
/// If allowed, the query is permitted and the supervisor resolves the
/// domain in a background thread, adding the resulting IPs to the
/// dynamic allowlist.
///
/// If no domain rules are configured (empty `allowed_domains`), DNS
/// traffic is subject to normal IP-based filtering.
fn evaluate_dns_sendto(
    notif: &SeccompNotif,
    policy: &NotifierPolicy,
    dynamic_allowlist: &DynamicAllowlist,
    dns_server_ip: &IpAddr,
    notifier_fd: RawFd,
) -> Verdict {
    let pid = notif.pid;
    let buf_ptr = notif.data.args[1];
    let buf_len = notif.data.args[2] as usize;

    // If no domain rules are configured, fall through to IP-based check.
    // This means DNS traffic to an allowed DNS server IP is permitted,
    // but the sandbox can't reach non-allowed IPs regardless.
    if policy.allowed_domains.is_empty() {
        tracing::debug!(pid, "DNS sendto: no domain rules, checking IP");
        return classify_outbound_ip(
            pid,
            *dns_server_ip,
            DNS_PORT,
            policy,
            dynamic_allowlist,
            "sendto(dns)",
        );
    }

    // The DNS server IP (from the namespace's resolv.conf, set by pasta)
    // must be reachable for DNS to work. Allow traffic to the DNS server
    // itself — the domain check filters at the query level.
    //
    // Typical DNS servers: the default gateway (pasta mirrors host config),
    // or loopback/link-local resolvers. These are already allowed by
    // classify_outbound_ip's special-case rules. For external DNS servers
    // (e.g., 8.8.8.8), we explicitly allow port 53 traffic here since
    // the domain-level filtering provides the actual security boundary.

    // Read the DNS query payload.
    let read_len = buf_len.min(DNS_MAX_INSPECT);
    if read_len < DNS_HEADER_SIZE {
        tracing::warn!(
            pid,
            buf_len,
            "DNS sendto: payload too small for DNS header, denying"
        );
        return Verdict::Deny(libc::EACCES as u32);
    }

    let payload = match read_proc_mem(pid, buf_ptr, read_len) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(pid, error = %e, "DNS sendto: failed to read payload, denying");
            return Verdict::Deny(libc::EACCES as u32);
        }
    };

    // TOCTOU re-check after reading payload.
    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(
            pid,
            "DNS sendto: notification invalidated after payload read"
        );
        return Verdict::Deny(libc::EPERM as u32);
    }

    // Extract the queried domain name.
    let domain = match extract_dns_query_name(&payload) {
        Some(d) => d,
        None => {
            tracing::warn!(pid, "DNS sendto: could not parse query name, denying");
            return Verdict::Deny(libc::EACCES as u32);
        }
    };

    // Check domain against the allowlist.
    if is_domain_allowed_by_policy(&domain, &policy.allowed_domains) {
        tracing::debug!(
            pid,
            domain,
            "DNS sendto: domain allowed, triggering resolution"
        );

        // Spawn a background thread to resolve the domain and populate
        // the dynamic allowlist. The supervisor process (PID 1 in the
        // sandbox namespace) has its own network access through pasta,
        // and its syscalls are NOT filtered by seccomp (only the worker's
        // are). This avoids recursion.
        let dyn_list = dynamic_allowlist.clone();
        let domain_owned = domain.clone();
        if let Err(e) = std::thread::Builder::new()
            .name(format!("dns-resolve-{domain}"))
            .spawn(move || {
                resolve_and_add(&domain_owned, &dyn_list);
            })
        {
            tracing::warn!(error = %e, domain, "failed to spawn resolver thread");
        }

        Verdict::Allow
    } else {
        tracing::warn!(pid, domain, "DNS sendto: domain denied by policy");
        Verdict::Deny(libc::EACCES as u32)
    }
}

/// Extract the query domain name from a DNS packet.
///
/// Parses the question section of a standard DNS query and returns the
/// first QNAME as a lowercase dotted string (e.g., "example.com").
///
/// Returns `None` for malformed packets, zero-question packets, or
/// packets using pointer compression in the question section.
fn extract_dns_query_name(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_SIZE {
        return None;
    }

    // QDCOUNT is at bytes 4-5.
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    // Question section starts at byte 12.
    let mut pos = DNS_HEADER_SIZE;
    let mut labels = Vec::new();

    loop {
        if pos >= packet.len() {
            return None;
        }

        let label_len = packet[pos] as usize;
        pos += 1;

        if label_len == 0 {
            break; // Root label — end of name.
        }

        // Pointer compression — not expected in queries, but handle gracefully.
        if label_len >= 0xC0 {
            return None;
        }

        if pos + label_len > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[pos..pos + label_len]).ok()?;
        labels.push(label.to_lowercase());
        pos += label_len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Check if a domain is allowed by the domain allowlist.
///
/// Uses suffix matching: `"example.com"` allows both `example.com`
/// and any subdomain like `www.example.com`.
fn is_domain_allowed_by_policy(domain: &str, allowed_domains: &[String]) -> bool {
    let normalized = domain.trim_end_matches('.');

    for allowed in allowed_domains {
        let allowed_normalized = allowed.trim_end_matches('.');
        if normalized == allowed_normalized
            || normalized.ends_with(&format!(".{allowed_normalized}"))
        {
            return true;
        }
    }

    false
}

/// Resolve a domain name and add the resulting IPs to the dynamic allowlist.
///
/// Runs in a background thread spawned by the supervisor. Uses the system
/// resolver (getaddrinfo), which in the supervisor's context goes through
/// pasta's network — the same resolver the sandbox process uses.
fn resolve_and_add(domain: &str, dynamic_allowlist: &DynamicAllowlist) {
    use std::net::ToSocketAddrs;

    match (domain, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if ips.is_empty() {
                tracing::warn!(domain, "resolver returned no addresses");
            } else {
                tracing::debug!(domain, ips = ?ips, "resolved domain, adding to dynamic allowlist");
                dynamic_allowlist.add_ips(ips);
            }
        }
        Err(e) => {
            tracing::warn!(domain, error = %e, "failed to resolve domain for dynamic allowlist");
        }
    }
}

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

    // Deny SOCK_RAW entirely.
    if sock_type == SOCK_RAW {
        tracing::warn!(pid, domain, "socket: SOCK_RAW denied");
        return Verdict::Deny(libc::EPERM as u32);
    }

    // Deny AF_NETLINK.
    if domain == AF_NETLINK {
        tracing::warn!(pid, "socket: AF_NETLINK denied");
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

    let pathname = match read_proc_string(pid, pathname_ptr, 4096) {
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
    let pathname = match read_proc_string(pid, pathname_ptr, 4096) {
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
pub fn policy_from_config(
    config: &can_policy::SandboxConfig,
    resolved_ips: &[(String, Vec<IpAddr>)],
) -> NotifierPolicy {
    let mut allowed_ips: HashSet<IpAddr> = HashSet::new();
    let mut allowed_cidrs: Vec<(IpAddr, u8)> = Vec::new();

    // Add pre-resolved IPs from whitelisted domains.
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

    // pasta infrastructure addresses — always allowed.
    // Allow the pasta DNS address (link-local) used by resolv.conf inside
    // the namespace. Pasta configures this as the nameserver; the actual
    // DNS filtering happens at the query level (domain allowlist check in
    // evaluate_dns_sendto).
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
    // Only restrict when the user has explicitly configured domain or IP
    // rules. Port-forwarding-only configs (no domains, no IPs) should
    // allow all outbound traffic — the notifier is still useful for
    // clone/socket/execve enforcement.
    let restrict_outbound =
        !config.network.allow_domains.is_empty() || !config.network.allow_ips.is_empty();

    NotifierPolicy {
        allowed_ips,
        allowed_cidrs,
        allowed_domains: config.network.allow_domains.clone(),
        allowed_exec_paths,
        allowed_exec_prefixes,
        allow_af_unix: true,
        allow_af_inet: true,
        restrict_outbound,
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
mod tests {
    use super::*;

    #[test]
    fn kernel_version_parsing() {
        assert_eq!(parse_kernel_version("5.9.0-generic"), Some((5, 9)));
        assert_eq!(parse_kernel_version("6.1.52"), Some((6, 1)));
        assert_eq!(parse_kernel_version("4.19.128-lts"), Some((4, 19)));
        assert_eq!(parse_kernel_version("5.15.0-76-generic"), Some((5, 15)));
    }

    #[test]
    fn kernel_version_detection_returns_bool() {
        // Just make sure it doesn't panic.
        let _ = is_notifier_supported();
    }

    #[test]
    fn notifier_filter_has_correct_structure() {
        let filter = build_notifier_filter();
        // arch_load, arch_cmp, arch_allow, nr_load, N checks, allow, user_notif
        let expected = 3 + 1 + NOTIFIED_SYSCALLS.len() + 1 + 1;
        assert_eq!(filter.len(), expected);

        // Last instruction should be USER_NOTIF.
        let last = filter.last().unwrap();
        assert_eq!(last.code, (libc::BPF_RET | libc::BPF_K) as u16);
        assert_eq!(last.k, SECCOMP_RET_USER_NOTIF);

        // Second-to-last should be ALLOW.
        let allow = &filter[filter.len() - 2];
        assert_eq!(allow.k, libc::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn ip_in_cidr_v4() {
        let net: IpAddr = "10.0.0.0".parse().unwrap();
        let ip_in: IpAddr = "10.255.255.255".parse().unwrap();
        let ip_out: IpAddr = "11.0.0.0".parse().unwrap();

        assert!(ip_in_cidr(ip_in, net, 8));
        assert!(!ip_in_cidr(ip_out, net, 8));
    }

    #[test]
    fn ip_in_cidr_v4_exact() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(ip_in_cidr(ip, ip, 32));
        assert!(!ip_in_cidr("192.168.1.2".parse().unwrap(), ip, 32));
    }

    #[test]
    fn ip_in_cidr_v6() {
        let net: IpAddr = "fd00::".parse().unwrap();
        let ip_in: IpAddr = "fd00::1".parse().unwrap();
        let ip_out: IpAddr = "fe80::1".parse().unwrap();

        assert!(ip_in_cidr(ip_in, net, 8));
        assert!(!ip_in_cidr(ip_out, net, 8));
    }

    #[test]
    fn ip_in_cidr_zero_prefix() {
        let any: IpAddr = "0.0.0.0".parse().unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(ip_in_cidr(ip, any, 0));
    }

    #[test]
    fn ip_in_cidr_v4_v6_mismatch() {
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        assert!(!ip_in_cidr(v4, v6, 8));
    }

    #[test]
    fn policy_loopback_always_allowed() {
        let policy = NotifierPolicy::default();
        assert!(policy.is_ip_allowed("127.0.0.1".parse().unwrap()));
        assert!(policy.is_ip_allowed("::1".parse().unwrap()));
    }

    #[test]
    fn policy_explicit_ip() {
        let mut policy = NotifierPolicy::default();
        policy.allowed_ips.insert("93.184.216.34".parse().unwrap());
        assert!(policy.is_ip_allowed("93.184.216.34".parse().unwrap()));
        assert!(!policy.is_ip_allowed("93.184.216.35".parse().unwrap()));
    }

    #[test]
    fn policy_cidr_range() {
        let mut policy = NotifierPolicy::default();
        policy
            .allowed_cidrs
            .push(("172.16.0.0".parse().unwrap(), 12));
        assert!(policy.is_ip_allowed("172.16.0.1".parse().unwrap()));
        assert!(policy.is_ip_allowed("172.31.255.255".parse().unwrap()));
        assert!(!policy.is_ip_allowed("172.32.0.0".parse().unwrap()));
    }

    #[test]
    fn parse_cidr_valid() {
        assert_eq!(
            parse_cidr("10.0.0.0/8"),
            Some(("10.0.0.0".parse().unwrap(), 8))
        );
        assert_eq!(
            parse_cidr("192.168.1.0/24"),
            Some(("192.168.1.0".parse().unwrap(), 24))
        );
    }

    #[test]
    fn parse_cidr_invalid() {
        assert_eq!(parse_cidr("10.0.0.0"), None);
        assert_eq!(parse_cidr("not-an-ip/8"), None);
        assert_eq!(parse_cidr(""), None);
    }

    #[test]
    fn clone_ns_flags_mask_is_complete() {
        // Verify our mask covers all namespace flags.
        assert_ne!(NS_FLAGS_MASK & CLONE_NEWNS, 0);
        assert_ne!(NS_FLAGS_MASK & CLONE_NEWPID, 0);
        assert_ne!(NS_FLAGS_MASK & CLONE_NEWNET, 0);
        assert_ne!(NS_FLAGS_MASK & CLONE_NEWUSER, 0);
        assert_ne!(NS_FLAGS_MASK & CLONE_NEWIPC, 0);
        assert_ne!(NS_FLAGS_MASK & CLONE_NEWUTS, 0);
        assert_ne!(NS_FLAGS_MASK & CLONE_NEWCGROUP, 0);
        assert_ne!(NS_FLAGS_MASK & CLONE_NEWTIME, 0);
    }

    #[test]
    fn seccomp_notif_struct_sizes() {
        assert_eq!(std::mem::size_of::<SeccompNotif>(), 80);
        assert_eq!(std::mem::size_of::<SeccompNotifResp>(), 24);
    }

    #[test]
    fn policy_from_config_adds_pasta_addrs() {
        use can_policy::SandboxConfig;
        let config = SandboxConfig::default_deny();
        let policy = policy_from_config(&config, &[]);
        // The pasta DNS address (link-local) must always be allowed.
        assert!(policy.is_ip_allowed(can_net::pasta::PASTA_DNS_ADDR.parse().unwrap()));
        // Note: default gateway depends on host, so we don't assert a specific IP.
    }

    #[test]
    fn policy_from_config_with_resolved_ips() {
        use can_policy::SandboxConfig;
        let config = SandboxConfig::default_deny();
        let resolved = vec![(
            "example.com".to_string(),
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()],
        )];
        let policy = policy_from_config(&config, &resolved);
        assert!(policy.is_ip_allowed("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn policy_from_config_with_cidr() {
        let mut config = can_policy::SandboxConfig::default_deny();
        config.network.allow_ips = vec!["10.0.0.0/8".to_string()];
        let policy = policy_from_config(&config, &[]);
        assert!(policy.is_ip_allowed("10.1.2.3".parse().unwrap()));
        assert!(!policy.is_ip_allowed("11.0.0.0".parse().unwrap()));
    }

    // ---- Evaluator unit tests ----
    //
    // These test the pure evaluation logic using synthetic syscall arguments.
    // They don't require actual seccomp filters or /proc/pid/mem.

    #[test]
    fn evaluate_clone_allows_plain_thread() {
        // CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
        // This is what pthread_create uses — no namespace flags.
        let flags: u64 = 0x0001_0F00; // typical thread flags
        let args = [flags, 0, 0, 0, 0, 0];
        match evaluate_clone(&args, 1234) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow, got Deny({e})"),
        }
    }

    #[test]
    fn evaluate_clone_denies_newpid() {
        let flags: u64 = CLONE_NEWPID;
        let args = [flags, 0, 0, 0, 0, 0];
        match evaluate_clone(&args, 1234) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for CLONE_NEWPID"),
        }
    }

    #[test]
    fn evaluate_clone_denies_newnet() {
        let flags: u64 = CLONE_NEWNET;
        let args = [flags, 0, 0, 0, 0, 0];
        match evaluate_clone(&args, 1234) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for CLONE_NEWNET"),
        }
    }

    #[test]
    fn evaluate_clone_denies_newuser() {
        let flags: u64 = CLONE_NEWUSER;
        let args = [flags, 0, 0, 0, 0, 0];
        match evaluate_clone(&args, 1234) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for CLONE_NEWUSER"),
        }
    }

    #[test]
    fn evaluate_clone_denies_combined_ns_flags() {
        let flags: u64 = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET;
        let args = [flags, 0, 0, 0, 0, 0];
        match evaluate_clone(&args, 1234) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for combined NS flags"),
        }
    }

    #[test]
    fn evaluate_clone_allows_zero_flags() {
        let args = [0u64, 0, 0, 0, 0, 0];
        match evaluate_clone(&args, 1234) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for zero flags, got Deny({e})"),
        }
    }

    #[test]
    fn evaluate_socket_allows_af_inet_stream() {
        let policy = NotifierPolicy::default();
        let args = [AF_INET, libc::SOCK_STREAM as u64, 0, 0, 0, 0];
        match evaluate_socket(&args, 1234, &policy) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for AF_INET SOCK_STREAM, got Deny({e})"),
        }
    }

    #[test]
    fn evaluate_socket_allows_af_inet6_dgram() {
        let policy = NotifierPolicy::default();
        let args = [AF_INET6, libc::SOCK_DGRAM as u64, 0, 0, 0, 0];
        match evaluate_socket(&args, 1234, &policy) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for AF_INET6 SOCK_DGRAM, got Deny({e})"),
        }
    }

    #[test]
    fn evaluate_socket_allows_af_unix() {
        let policy = NotifierPolicy::default();
        let args = [AF_UNIX, libc::SOCK_STREAM as u64, 0, 0, 0, 0];
        match evaluate_socket(&args, 1234, &policy) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for AF_UNIX, got Deny({e})"),
        }
    }

    #[test]
    fn evaluate_socket_denies_af_netlink() {
        let policy = NotifierPolicy::default();
        let args = [AF_NETLINK, libc::SOCK_DGRAM as u64, 0, 0, 0, 0];
        match evaluate_socket(&args, 1234, &policy) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for AF_NETLINK"),
        }
    }

    #[test]
    fn evaluate_socket_denies_sock_raw() {
        let policy = NotifierPolicy::default();
        let args = [AF_INET, SOCK_RAW, 0, 0, 0, 0];
        match evaluate_socket(&args, 1234, &policy) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for SOCK_RAW"),
        }
    }

    #[test]
    fn evaluate_socket_respects_allow_af_unix_false() {
        let policy = NotifierPolicy {
            allow_af_unix: false,
            ..Default::default()
        };
        let args = [AF_UNIX, libc::SOCK_STREAM as u64, 0, 0, 0, 0];
        match evaluate_socket(&args, 1234, &policy) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny when allow_af_unix is false"),
        }
    }

    #[test]
    fn evaluate_socket_respects_allow_af_inet_false() {
        let policy = NotifierPolicy {
            allow_af_inet: false,
            ..Default::default()
        };
        let args = [AF_INET, libc::SOCK_STREAM as u64, 0, 0, 0, 0];
        match evaluate_socket(&args, 1234, &policy) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny when allow_af_inet is false"),
        }
    }

    #[test]
    fn evaluate_socket_denies_unknown_domain() {
        let policy = NotifierPolicy::default();
        let args = [99u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0];
        match evaluate_socket(&args, 1234, &policy) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for unknown domain 99"),
        }
    }

    #[test]
    fn evaluate_socket_strips_cloexec_from_type() {
        // SOCK_STREAM | SOCK_CLOEXEC should still be treated as SOCK_STREAM.
        let policy = NotifierPolicy::default();
        let sock_type = libc::SOCK_STREAM as u64 | libc::SOCK_CLOEXEC as u64;
        let args = [AF_INET, sock_type, 0, 0, 0, 0];
        match evaluate_socket(&args, 1234, &policy) {
            Verdict::Allow => {}
            Verdict::Deny(e) => {
                panic!("expected Allow for SOCK_STREAM|SOCK_CLOEXEC, got Deny({e})")
            }
        }
    }

    #[test]
    fn notifier_filter_jump_offsets_correct() {
        let filter = build_notifier_filter();
        let n = NOTIFIED_SYSCALLS.len();

        // Checks start at index 4 (after arch_load, arch_cmp, arch_allow, nr_load).
        // For each check at position i (0-indexed within checks):
        //   jt = (n - 1 - i) + 1 = n - i (skip remaining checks + ALLOW → USER_NOTIF)
        //   jf = 0 (fall through)
        for i in 0..n {
            let instr = &filter[4 + i];
            let expected_jt = (n - i) as u8;
            assert_eq!(
                instr.jt, expected_jt,
                "check[{i}] jt: expected {expected_jt}, got {}",
                instr.jt
            );
            assert_eq!(instr.jf, 0, "check[{i}] jf should be 0");
        }
    }

    #[test]
    fn notifier_filter_checks_correct_syscalls() {
        let filter = build_notifier_filter();
        // Extract the syscall numbers from the BPF check instructions.
        let checked_nrs: Vec<u32> = (0..NOTIFIED_SYSCALLS.len())
            .map(|i| filter[4 + i].k)
            .collect();

        let expected_nrs: Vec<u32> = NOTIFIED_SYSCALLS.iter().map(|(_, nr)| *nr as u32).collect();

        assert_eq!(checked_nrs, expected_nrs);
    }

    #[test]
    fn notified_syscalls_list_covers_expected() {
        let names: Vec<&str> = NOTIFIED_SYSCALLS.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"connect"));
        assert!(names.contains(&"clone"));
        assert!(names.contains(&"clone3"));
        assert!(names.contains(&"socket"));
        assert!(names.contains(&"execve"));
        assert!(names.contains(&"execveat"));
        assert!(names.contains(&"sendto"));
        assert!(names.contains(&"sendmsg"));
    }

    #[test]
    fn policy_default_allows_af_unix_and_inet() {
        let policy = NotifierPolicy::default();
        assert!(policy.allow_af_unix);
        assert!(policy.allow_af_inet);
    }

    #[test]
    fn policy_non_loopback_non_listed_denied() {
        let policy = NotifierPolicy::default();
        // A random public IP should be denied by default.
        assert!(!policy.is_ip_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn ip_in_cidr_invalid_prefix_returns_false() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let net: IpAddr = "10.0.0.0".parse().unwrap();
        // Prefix > 32 for IPv4 should return false.
        assert!(!ip_in_cidr(ip, net, 33));
    }

    #[test]
    fn ip_in_cidr_v6_invalid_prefix_returns_false() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        let net: IpAddr = "fd00::".parse().unwrap();
        assert!(!ip_in_cidr(ip, net, 129));
    }

    // ---- is_exec_path_allowed unit tests ----

    #[test]
    fn exec_path_exact_match() {
        let mut policy = NotifierPolicy::default();
        policy
            .allowed_exec_paths
            .insert(PathBuf::from("/usr/bin/python3"));
        assert!(is_exec_path_allowed(Path::new("/usr/bin/python3"), &policy));
        assert!(!is_exec_path_allowed(
            Path::new("/usr/bin/python2"),
            &policy
        ));
    }

    #[test]
    fn exec_path_prefix_match() {
        let mut policy = NotifierPolicy::default();
        policy
            .allowed_exec_prefixes
            .push(PathBuf::from("/nix/store"));
        assert!(is_exec_path_allowed(
            Path::new("/nix/store/abc123/bin/mix"),
            &policy
        ));
        assert!(is_exec_path_allowed(
            Path::new("/nix/store/xyz/lib/erlang/bin/beam.smp"),
            &policy
        ));
    }

    #[test]
    fn exec_path_prefix_rejects_partial_dir_match() {
        let mut policy = NotifierPolicy::default();
        policy
            .allowed_exec_prefixes
            .push(PathBuf::from("/nix/store"));
        // "/nix/store-extra/bin" should NOT match "/nix/store/*".
        assert!(!is_exec_path_allowed(
            Path::new("/nix/store-extra/bin/foo"),
            &policy
        ));
    }

    #[test]
    fn exec_path_prefix_rejects_exact_prefix_without_slash() {
        let mut policy = NotifierPolicy::default();
        policy
            .allowed_exec_prefixes
            .push(PathBuf::from("/nix/store"));
        // The prefix directory itself (no trailing /) should not match.
        assert!(!is_exec_path_allowed(Path::new("/nix/store"), &policy));
    }

    #[test]
    fn exec_path_empty_policy_denies_nothing() {
        let policy = NotifierPolicy::default();
        // With empty paths AND prefixes, is_exec_path_allowed returns false.
        // But evaluate_execve short-circuits to Allow when both are empty.
        assert!(!is_exec_path_allowed(Path::new("/any/path"), &policy));
    }

    // ---- classify_connect_addr unit tests ----
    //
    // These test the address classification logic extracted from
    // evaluate_connect() using synthetic sockaddr byte arrays.

    /// Build a synthetic sockaddr_in byte array.
    fn make_sockaddr_in(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let family = (libc::AF_INET as u16).to_ne_bytes();
        let port_bytes = port.to_be_bytes();
        let octets = ip.octets();
        let mut buf = vec![0u8; 16]; // sockaddr_in is 16 bytes
        buf[0..2].copy_from_slice(&family);
        buf[2..4].copy_from_slice(&port_bytes);
        buf[4..8].copy_from_slice(&octets);
        buf
    }

    /// Build a synthetic sockaddr_in6 byte array.
    fn make_sockaddr_in6(ip: Ipv6Addr, port: u16) -> Vec<u8> {
        let family = (libc::AF_INET6 as u16).to_ne_bytes();
        let port_bytes = port.to_be_bytes();
        let octets = ip.octets();
        let mut buf = vec![0u8; 28]; // sockaddr_in6 is 28 bytes
        buf[0..2].copy_from_slice(&family);
        buf[2..4].copy_from_slice(&port_bytes);
        // bytes 4-7 = flowinfo (zero)
        buf[8..24].copy_from_slice(&octets);
        // bytes 24-27 = scope_id (zero)
        buf
    }

    /// Build a synthetic sockaddr with just a family (for AF_UNSPEC etc.).
    fn make_sockaddr_family(family: i32) -> Vec<u8> {
        let family_bytes = (family as u16).to_ne_bytes();
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&family_bytes);
        buf
    }

    #[test]
    fn connect_af_unspec_allowed() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_family(libc::AF_UNSPEC);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for AF_UNSPEC, got Deny({e})"),
        }
    }

    #[test]
    fn connect_af_unix_allowed() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_family(libc::AF_UNIX);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for AF_UNIX, got Deny({e})"),
        }
    }

    #[test]
    fn connect_ipv4_unspecified_allowed() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in(Ipv4Addr::UNSPECIFIED, 0);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for 0.0.0.0, got Deny({e})"),
        }
    }

    #[test]
    fn connect_ipv6_unspecified_allowed() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in6(Ipv6Addr::UNSPECIFIED, 0);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for ::, got Deny({e})"),
        }
    }

    #[test]
    fn connect_ipv4_loopback_allowed() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in(Ipv4Addr::LOCALHOST, 8080);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for 127.0.0.1, got Deny({e})"),
        }
    }

    #[test]
    fn connect_ipv6_loopback_allowed() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in6(Ipv6Addr::LOCALHOST, 8080);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for ::1, got Deny({e})"),
        }
    }

    #[test]
    fn connect_pasta_dns_addr_allowed() {
        let policy = NotifierPolicy::default();
        let dns_ip: Ipv4Addr = PASTA_DNS_ADDR.parse().unwrap();
        let addr = make_sockaddr_in(dns_ip, 53);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => {
                panic!("expected Allow for pasta DNS {PASTA_DNS_ADDR}, got Deny({e})")
            }
        }
    }

    #[test]
    fn connect_other_link_local_denied() {
        // AWS metadata endpoint 169.254.169.254 should be denied.
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in(Ipv4Addr::new(169, 254, 169, 254), 80);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for 169.254.169.254"),
        }
    }

    #[test]
    fn connect_ipv4_multicast_denied() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in(Ipv4Addr::new(224, 0, 0, 1), 5353);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for multicast 224.0.0.1"),
        }
    }

    #[test]
    fn connect_ipv6_multicast_denied() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in6("ff02::1".parse().unwrap(), 5353);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for IPv6 multicast ff02::1"),
        }
    }

    #[test]
    fn connect_ipv4_broadcast_denied() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in(Ipv4Addr::BROADCAST, 1234);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for broadcast 255.255.255.255"),
        }
    }

    #[test]
    fn connect_ipv6_link_local_denied() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in6("fe80::1".parse().unwrap(), 80);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for IPv6 link-local fe80::1"),
        }
    }

    #[test]
    fn connect_unknown_family_denied() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_family(99);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for unknown family 99"),
        }
    }

    #[test]
    fn connect_policy_allowed_ip() {
        let mut policy = NotifierPolicy::default();
        policy.allowed_ips.insert("93.184.216.34".parse().unwrap());
        let addr = make_sockaddr_in(Ipv4Addr::new(93, 184, 216, 34), 443);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for policy-allowed IP, got Deny({e})"),
        }
    }

    #[test]
    fn connect_policy_denied_ip() {
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in(Ipv4Addr::new(8, 8, 8, 8), 53);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for non-allowed IP 8.8.8.8"),
        }
    }

    #[test]
    fn connect_af_inet_too_short_denied() {
        let policy = NotifierPolicy::default();
        // AF_INET with only 4 bytes (less than required 8).
        let family = (libc::AF_INET as u16).to_ne_bytes();
        let mut addr = vec![0u8; 4];
        addr[0..2].copy_from_slice(&family);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for truncated AF_INET sockaddr"),
        }
    }

    #[test]
    fn connect_af_inet6_too_short_denied() {
        let policy = NotifierPolicy::default();
        // AF_INET6 with only 16 bytes (less than required 24).
        let family = (libc::AF_INET6 as u16).to_ne_bytes();
        let mut addr = vec![0u8; 16];
        addr[0..2].copy_from_slice(&family);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for truncated AF_INET6 sockaddr"),
        }
    }

    #[test]
    fn policy_from_config_splits_prefix_rules() {
        let mut config = can_policy::SandboxConfig::default_deny();
        config.process.allow_execve = vec![
            PathBuf::from("/usr/bin/python3"),
            PathBuf::from("/nix/store/*"),
        ];
        let policy = policy_from_config(&config, &[]);
        // Exact path should be in allowed_exec_paths.
        // "/usr/bin/python3" may or may not canonicalize depending on fs,
        // but "/nix/store/*" should produce a prefix, not an exact path.
        assert_eq!(policy.allowed_exec_prefixes.len(), 1);
        // The prefix should be "/nix/store" (without the /*).
        assert_eq!(policy.allowed_exec_prefixes[0], PathBuf::from("/nix/store"));
        // Exact paths count: at least 1 ("/usr/bin/python3" or its canonical).
        assert!(!policy.allowed_exec_paths.is_empty());
    }

    // ---- DNS query name extraction tests ----

    /// Build a minimal DNS query packet for testing.
    fn build_test_query(domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        // Header: ID=0x1234, QR=0, OPCODE=0, RD=1
        packet.extend_from_slice(&[
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ]);
        // Question: encode domain name as labels.
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Root label
        // QTYPE=A (1), QCLASS=IN (1)
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        packet
    }

    #[test]
    fn dns_extract_simple_domain() {
        let query = build_test_query("example.com");
        assert_eq!(
            extract_dns_query_name(&query),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn dns_extract_subdomain() {
        let query = build_test_query("www.example.com");
        assert_eq!(
            extract_dns_query_name(&query),
            Some("www.example.com".to_string())
        );
    }

    #[test]
    fn dns_extract_single_label() {
        let query = build_test_query("localhost");
        assert_eq!(
            extract_dns_query_name(&query),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn dns_extract_deep_subdomain() {
        let query = build_test_query("a.b.c.d.example.com");
        assert_eq!(
            extract_dns_query_name(&query),
            Some("a.b.c.d.example.com".to_string())
        );
    }

    #[test]
    fn dns_extract_case_insensitive() {
        let query = build_test_query("Example.COM");
        assert_eq!(
            extract_dns_query_name(&query),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn dns_extract_short_packet_returns_none() {
        let packet = [0u8; 4];
        assert_eq!(extract_dns_query_name(&packet), None);
    }

    #[test]
    fn dns_extract_zero_qdcount_returns_none() {
        let mut query = build_test_query("example.com");
        query[4] = 0;
        query[5] = 0; // QDCOUNT=0
        assert_eq!(extract_dns_query_name(&query), None);
    }

    #[test]
    fn dns_extract_truncated_label_returns_none() {
        // Build a packet that claims a label of length 10 but only has 3 bytes.
        let mut packet = vec![0u8; DNS_HEADER_SIZE + 2];
        packet[4] = 0x00;
        packet[5] = 0x01; // QDCOUNT=1
        packet[DNS_HEADER_SIZE] = 10; // label_len = 10, but only 1 byte follows
        packet[DNS_HEADER_SIZE + 1] = b'a';
        assert_eq!(extract_dns_query_name(&packet), None);
    }

    #[test]
    fn dns_extract_pointer_compression_returns_none() {
        // Pointer compression byte (0xC0+) should cause None in query names.
        let mut packet = vec![0u8; DNS_HEADER_SIZE + 2];
        packet[4] = 0x00;
        packet[5] = 0x01; // QDCOUNT=1
        packet[DNS_HEADER_SIZE] = 0xC0; // pointer
        packet[DNS_HEADER_SIZE + 1] = 0x00;
        assert_eq!(extract_dns_query_name(&packet), None);
    }

    #[test]
    fn dns_extract_header_only_no_question_returns_none() {
        // Header with QDCOUNT=1 but no actual question data.
        let mut packet = vec![0u8; DNS_HEADER_SIZE];
        packet[4] = 0x00;
        packet[5] = 0x01;
        assert_eq!(extract_dns_query_name(&packet), None);
    }

    // ---- Domain matching tests ----

    #[test]
    fn domain_allowed_exact_match() {
        let allowed = vec!["example.com".to_string()];
        assert!(is_domain_allowed_by_policy("example.com", &allowed));
    }

    #[test]
    fn domain_allowed_subdomain_match() {
        let allowed = vec!["example.com".to_string()];
        assert!(is_domain_allowed_by_policy("www.example.com", &allowed));
    }

    #[test]
    fn domain_allowed_deep_subdomain_match() {
        let allowed = vec!["example.com".to_string()];
        assert!(is_domain_allowed_by_policy("a.b.c.example.com", &allowed));
    }

    #[test]
    fn domain_denied_different_domain() {
        let allowed = vec!["example.com".to_string()];
        assert!(!is_domain_allowed_by_policy("evil.com", &allowed));
    }

    #[test]
    fn domain_denied_partial_suffix() {
        // "notexample.com" should NOT match "example.com".
        let allowed = vec!["example.com".to_string()];
        assert!(!is_domain_allowed_by_policy("notexample.com", &allowed));
    }

    #[test]
    fn domain_allowed_trailing_dot_normalized() {
        let allowed = vec!["example.com.".to_string()];
        assert!(is_domain_allowed_by_policy("example.com", &allowed));
        assert!(is_domain_allowed_by_policy("example.com.", &allowed));
    }

    #[test]
    fn domain_allowed_multiple_domains() {
        let allowed = vec!["example.com".to_string(), "github.com".to_string()];
        assert!(is_domain_allowed_by_policy("api.github.com", &allowed));
        assert!(is_domain_allowed_by_policy("example.com", &allowed));
        assert!(!is_domain_allowed_by_policy("evil.com", &allowed));
    }

    #[test]
    fn domain_denied_empty_allowlist() {
        let allowed: Vec<String> = vec![];
        assert!(!is_domain_allowed_by_policy("example.com", &allowed));
    }

    // ---- DynamicAllowlist tests ----

    #[test]
    fn dynamic_allowlist_new_is_empty() {
        let al = DynamicAllowlist::new();
        assert!(!al.contains(&"1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn dynamic_allowlist_add_and_contains() {
        let al = DynamicAllowlist::new();
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        al.add_ips(vec![ip]);
        assert!(al.contains(&ip));
    }

    #[test]
    fn dynamic_allowlist_add_multiple() {
        let al = DynamicAllowlist::new();
        let ips: Vec<IpAddr> = vec![
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            "::1".parse().unwrap(),
        ];
        al.add_ips(ips.clone());
        for ip in &ips {
            assert!(al.contains(ip));
        }
    }

    #[test]
    fn dynamic_allowlist_not_contains_unlisted() {
        let al = DynamicAllowlist::new();
        al.add_ips(vec!["1.2.3.4".parse().unwrap()]);
        assert!(!al.contains(&"5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn dynamic_allowlist_clone_shares_state() {
        let al = DynamicAllowlist::new();
        let al2 = al.clone();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        al.add_ips(vec![ip]);
        // Clone should see the same data (Arc-shared).
        assert!(al2.contains(&ip));
    }

    #[test]
    fn dynamic_allowlist_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let al = Arc::new(DynamicAllowlist::new());
        let mut handles = vec![];

        // Spawn 10 threads, each adding a unique IP.
        for i in 0..10u8 {
            let al = Arc::clone(&al);
            handles.push(thread::spawn(move || {
                let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
                al.add_ips(vec![ip]);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // All IPs should be present.
        for i in 0..10u8 {
            let ip: IpAddr = format!("10.0.0.{i}").parse().unwrap();
            assert!(al.contains(&ip), "expected 10.0.0.{i} in allowlist");
        }
    }

    // ---- classify_outbound_ip tests ----

    #[test]
    fn outbound_ip_loopback_allowed() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        match classify_outbound_ip(1, "127.0.0.1".parse().unwrap(), 80, &policy, &al, "test") {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for loopback, got Deny({e})"),
        }
    }

    #[test]
    fn outbound_ip_unspecified_allowed() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        match classify_outbound_ip(1, "0.0.0.0".parse().unwrap(), 0, &policy, &al, "test") {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for unspecified, got Deny({e})"),
        }
    }

    #[test]
    fn outbound_ip_multicast_denied() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        match classify_outbound_ip(1, "224.0.0.1".parse().unwrap(), 5353, &policy, &al, "test") {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for multicast"),
        }
    }

    #[test]
    fn outbound_ip_broadcast_denied() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        match classify_outbound_ip(
            1,
            "255.255.255.255".parse().unwrap(),
            1234,
            &policy,
            &al,
            "test",
        ) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for broadcast"),
        }
    }

    #[test]
    fn outbound_ip_pasta_dns_allowed() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        let dns_ip: IpAddr = PASTA_DNS_ADDR.parse().unwrap();
        match classify_outbound_ip(1, dns_ip, 53, &policy, &al, "test") {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for pasta DNS, got Deny({e})"),
        }
    }

    #[test]
    fn outbound_ip_link_local_denied() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        match classify_outbound_ip(
            1,
            "169.254.169.254".parse().unwrap(),
            80,
            &policy,
            &al,
            "test",
        ) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for link-local"),
        }
    }

    #[test]
    fn outbound_ip_static_policy_allows() {
        let mut policy = NotifierPolicy::default();
        policy.allowed_ips.insert("93.184.216.34".parse().unwrap());
        let al = DynamicAllowlist::new();
        match classify_outbound_ip(
            1,
            "93.184.216.34".parse().unwrap(),
            443,
            &policy,
            &al,
            "test",
        ) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for policy IP, got Deny({e})"),
        }
    }

    #[test]
    fn outbound_ip_dynamic_allowlist_allows() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        al.add_ips(vec!["93.184.216.34".parse().unwrap()]);
        match classify_outbound_ip(
            1,
            "93.184.216.34".parse().unwrap(),
            443,
            &policy,
            &al,
            "test",
        ) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for dynamic-allowed IP, got Deny({e})"),
        }
    }

    #[test]
    fn outbound_ip_denied_when_not_in_either_list() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        match classify_outbound_ip(1, "8.8.8.8".parse().unwrap(), 53, &policy, &al, "test") {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for non-allowed IP"),
        }
    }

    // ---- classify_sendto_addr tests ----
    //
    // These require a SeccompNotif which we can't easily construct without
    // real seccomp. Instead, we test the underlying classify_outbound_ip
    // and the DNS functions separately.

    // ---- policy_from_config with allowed_domains ----

    #[test]
    fn policy_from_config_includes_allowed_domains() {
        let mut config = can_policy::SandboxConfig::default_deny();
        config.network.allow_domains = vec!["example.com".to_string(), "github.com".to_string()];
        let policy = policy_from_config(&config, &[]);
        assert_eq!(policy.allowed_domains.len(), 2);
        assert!(policy.allowed_domains.contains(&"example.com".to_string()));
        assert!(policy.allowed_domains.contains(&"github.com".to_string()));
    }

    #[test]
    fn policy_from_config_empty_domains() {
        let config = can_policy::SandboxConfig::default_deny();
        let policy = policy_from_config(&config, &[]);
        assert!(policy.allowed_domains.is_empty());
    }

    // ---- connect uses dynamic allowlist ----

    #[test]
    fn connect_dynamic_allowlist_allows_ip() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        al.add_ips(vec!["93.184.216.34".parse().unwrap()]);
        let addr = make_sockaddr_in(Ipv4Addr::new(93, 184, 216, 34), 443);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &al) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow via dynamic allowlist, got Deny({e})"),
        }
    }

    #[test]
    fn connect_dynamic_allowlist_does_not_allow_unlisted() {
        let policy = NotifierPolicy::default();
        let al = DynamicAllowlist::new();
        al.add_ips(vec!["93.184.216.34".parse().unwrap()]);
        let addr = make_sockaddr_in(Ipv4Addr::new(8, 8, 8, 8), 53);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &al) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny for IP not in dynamic allowlist"),
        }
    }

    // ---- restrict_outbound tests ----

    #[test]
    fn policy_from_config_restrict_outbound_with_domains() {
        let mut config = can_policy::SandboxConfig::default_deny();
        config.network.allow_domains = vec!["example.com".to_string()];
        let policy = policy_from_config(&config, &[]);
        assert!(
            policy.restrict_outbound,
            "restrict_outbound should be true when domains are configured"
        );
    }

    #[test]
    fn policy_from_config_restrict_outbound_with_ips() {
        let mut config = can_policy::SandboxConfig::default_deny();
        config.network.allow_ips = vec!["1.2.3.4".to_string()];
        let policy = policy_from_config(&config, &[]);
        assert!(
            policy.restrict_outbound,
            "restrict_outbound should be true when IPs are configured"
        );
    }

    #[test]
    fn policy_from_config_no_restrict_outbound_ports_only() {
        let config = can_policy::SandboxConfig::default_deny();
        // No domains, no IPs — port-forwarding-only config.
        let policy = policy_from_config(&config, &[]);
        assert!(
            !policy.restrict_outbound,
            "restrict_outbound should be false when no domains or IPs are configured"
        );
    }

    #[test]
    fn connect_unrestricted_allows_any_ipv4() {
        let policy = NotifierPolicy {
            restrict_outbound: false,
            ..Default::default()
        };
        // Arbitrary public IP that is not in any allowlist.
        let addr = make_sockaddr_in(Ipv4Addr::new(198, 51, 100, 1), 443);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => {
                panic!("expected Allow with restrict_outbound=false, got Deny({e})")
            }
        }
    }

    #[test]
    fn connect_unrestricted_allows_any_ipv6() {
        let policy = NotifierPolicy {
            restrict_outbound: false,
            ..Default::default()
        };
        let addr = make_sockaddr_in6("2001:db8::1".parse().unwrap(), 80);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => {
                panic!("expected Allow with restrict_outbound=false, got Deny({e})")
            }
        }
    }

    #[test]
    fn connect_unrestricted_still_allows_af_unix() {
        let policy = NotifierPolicy {
            restrict_outbound: false,
            ..Default::default()
        };
        let addr = make_sockaddr_family(libc::AF_UNIX);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => panic!("expected Allow for AF_UNIX, got Deny({e})"),
        }
    }

    #[test]
    fn connect_restricted_denies_unlisted_ip() {
        // restrict_outbound defaults to true, but be explicit for clarity.
        let policy = NotifierPolicy::default();
        let addr = make_sockaddr_in(Ipv4Addr::new(198, 51, 100, 1), 443);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Deny(_) => {}
            Verdict::Allow => panic!("expected Deny with restrict_outbound=true and no allowlist"),
        }
    }

    #[test]
    fn connect_unrestricted_allows_multicast() {
        // When outbound is unrestricted, even multicast should be allowed
        // (the user chose not to restrict network at all).
        let policy = NotifierPolicy {
            restrict_outbound: false,
            ..Default::default()
        };
        let addr = make_sockaddr_in(Ipv4Addr::new(224, 0, 0, 1), 5353);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => {
                panic!("expected Allow with restrict_outbound=false, got Deny({e})")
            }
        }
    }

    #[test]
    fn connect_unrestricted_allows_link_local() {
        let policy = NotifierPolicy {
            restrict_outbound: false,
            ..Default::default()
        };
        let addr = make_sockaddr_in(Ipv4Addr::new(169, 254, 169, 254), 80);
        match classify_connect_addr(1, &addr, addr.len(), &policy, &DynamicAllowlist::new()) {
            Verdict::Allow => {}
            Verdict::Deny(e) => {
                panic!("expected Allow with restrict_outbound=false, got Deny({e})")
            }
        }
    }
}
