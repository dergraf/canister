//! Seccomp BPF filter generation and application.
//!
//! Generates classic BPF programs from the default [`SeccompProfile`] baseline
//! with recipe-level syscall overrides, and applies them via
//! `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`.
//!
//! Supports two enforcement modes:
//!
//! **Allow-list** (default deny):
//! ```text
//! [0]  load seccomp_data.arch
//! [1]  if arch != NATIVE → KILL_PROCESS
//! [2]  load seccomp_data.nr
//! [3]  if nr == allowed_0 → ALLOW
//! [4]  if nr == allowed_1 → ALLOW
//! ...
//! [N]  return DENY (ERRNO/KILL_PROCESS)
//! ```
//!
//! **Deny-list** (default allow):
//! ```text
//! [0]  load seccomp_data.arch
//! [1]  if arch != NATIVE → KILL_PROCESS
//! [2]  load seccomp_data.nr
//! [3]  if nr == denied_0 → DENY
//! [4]  if nr == denied_1 → DENY
//! ...
//! [N]  return ALLOW
//! ```
//!
//! Architecture validation always uses KILL_PROCESS regardless of mode,
//! preventing bypasses via x32 ABI on x86_64 or similar cross-arch attacks.

use can_policy::{SeccompMode, SeccompProfile, SyscallConfig};

/// Errors from seccomp filter operations.
#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("unknown syscall in profile: {0}")]
    UnknownSyscall(String),

    #[error("empty filter (no syscalls to deny)")]
    EmptyFilter,

    #[error("prctl(PR_SET_NO_NEW_PRIVS) failed: {0}")]
    NoNewPrivs(std::io::Error),

    #[error("prctl(PR_SET_SECCOMP) failed: {0}")]
    SetSeccomp(std::io::Error),

    #[error("seccomp not supported on this architecture")]
    UnsupportedArch,

    #[error("failed to resolve seccomp baseline: {0}")]
    BaselineResolution(String),
}

/// What action to take when a denied syscall is invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyAction {
    /// Kill the entire process (SECCOMP_RET_KILL_PROCESS).
    KillProcess,

    /// Return EPERM to the caller (SECCOMP_RET_ERRNO | EPERM).
    /// More graceful — allows the process to handle the error.
    Errno,

    /// Log the syscall but allow it to proceed (SECCOMP_RET_LOG).
    /// Used in monitor mode to observe what would be blocked without
    /// actually blocking it. Logged syscalls appear in kernel audit log
    /// (dmesg / journalctl).
    Log,
}

// --- Architecture constants ---
// AUDIT_ARCH_X86_64 = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE
// = 62 | 0x80000000 | 0x40000000 = 0xC000_003E
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;

// Offset of `arch` field in `struct seccomp_data` (bytes).
const OFFSET_ARCH: u32 = 4;
// Offset of `nr` field in `struct seccomp_data` (bytes).
const OFFSET_NR: u32 = 0;

// SECCOMP_RET_LOG: allow the syscall but log it via audit.
// Available since Linux 4.14. Not yet exposed by all versions of the libc crate.
const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;

/// Build a BPF filter program from a seccomp profile.
///
/// The `mode` parameter selects the enforcement model:
/// - **AllowList**: default action is `action` (deny). Syscalls in
///   `allow_syscalls` jump to ALLOW. Unknown syscalls are blocked.
/// - **DenyList**: default action is ALLOW. Syscalls in `deny_syscalls`
///   jump to `action` (deny). Unknown syscalls are allowed.
pub fn build_filter(
    profile: &SeccompProfile,
    action: DenyAction,
    mode: SeccompMode,
) -> Result<Vec<libc::sock_filter>, SeccompError> {
    match mode {
        SeccompMode::AllowList => build_allow_filter(profile, action),
        SeccompMode::DenyList => build_deny_filter(profile, action),
    }
}

/// Build an allow-list filter (default DENY, explicit allows).
///
/// Layout:
/// ```text
/// [0]  load arch → if mismatch → KILL_PROCESS
/// [3]  load nr
/// [4]  if nr == allowed_0 → jump to ALLOW
/// ...
/// [N]  return DENY (default action for unrecognized syscalls)
/// [N+1] return ALLOW (target of matched jumps)
/// ```
fn build_allow_filter(
    profile: &SeccompProfile,
    action: DenyAction,
) -> Result<Vec<libc::sock_filter>, SeccompError> {
    let allowed_nrs = resolve_syscall_numbers(&profile.allow_syscalls)?;

    if allowed_nrs.is_empty() {
        return Err(SeccompError::EmptyFilter);
    }

    let deny_ret = match action {
        DenyAction::KillProcess => libc::SECCOMP_RET_KILL_PROCESS,
        DenyAction::Errno => libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        DenyAction::Log => SECCOMP_RET_LOG,
    };

    let mut filter: Vec<libc::sock_filter> = vec![
        // [0] Load architecture
        bpf_stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            OFFSET_ARCH,
        ),
        // [1] Validate architecture: if native → skip kill
        bpf_jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            AUDIT_ARCH_NATIVE,
            1,
            0,
        ),
        // [2] Architecture mismatch → always kill
        bpf_stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_KILL_PROCESS,
        ),
        // [3] Load syscall number
        bpf_stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            OFFSET_NR,
        ),
    ];

    // For each allowed syscall: if nr matches → jump to ALLOW (at the end).
    // Layout after checks: [DENY] [ALLOW]
    // For check at index i with `remaining = n-1-i` checks after it:
    //   jt = remaining + 1 (skip remaining checks + DENY → land on ALLOW)
    //   jf = 0 (fall through to next check, or to DENY if last)
    for (i, &nr) in allowed_nrs.iter().enumerate() {
        let remaining = (allowed_nrs.len() - 1 - i) as u8;
        filter.push(bpf_jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            nr as u32,
            remaining + 1, // jt: skip remaining checks + DENY → ALLOW
            0,             // jf: fall through
        ));
    }

    // Default: deny (no check matched → syscall not in allow list).
    filter.push(bpf_stmt((libc::BPF_RET | libc::BPF_K) as u16, deny_ret));

    // Allow (reached when a check matched and jumped here).
    filter.push(bpf_stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        libc::SECCOMP_RET_ALLOW,
    ));

    Ok(filter)
}

/// Build a deny-list filter (default ALLOW, explicit denies).
///
/// Layout:
/// ```text
/// [0]  load arch → if mismatch → KILL_PROCESS
/// [3]  load nr
/// [4]  if nr == denied_0 → jump to DENY
/// ...
/// [N]  return ALLOW (default action for unrecognized syscalls)
/// [N+1] return DENY
/// ```
fn build_deny_filter(
    profile: &SeccompProfile,
    action: DenyAction,
) -> Result<Vec<libc::sock_filter>, SeccompError> {
    let denied_nrs = resolve_syscall_numbers(&profile.deny_syscalls)?;

    if denied_nrs.is_empty() {
        return Err(SeccompError::EmptyFilter);
    }

    let deny_ret = match action {
        DenyAction::KillProcess => libc::SECCOMP_RET_KILL_PROCESS,
        DenyAction::Errno => libc::SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        DenyAction::Log => SECCOMP_RET_LOG,
    };

    let mut filter: Vec<libc::sock_filter> = vec![
        bpf_stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            OFFSET_ARCH,
        ),
        bpf_jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            AUDIT_ARCH_NATIVE,
            1,
            0,
        ),
        bpf_stmt(
            (libc::BPF_RET | libc::BPF_K) as u16,
            libc::SECCOMP_RET_KILL_PROCESS,
        ),
        bpf_stmt(
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            OFFSET_NR,
        ),
    ];

    for (i, &nr) in denied_nrs.iter().enumerate() {
        let remaining = (denied_nrs.len() - 1 - i) as u8;
        filter.push(bpf_jump(
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            nr as u32,
            remaining + 1, // jt: skip remaining checks + ALLOW → DENY
            0,             // jf: fall through
        ));
    }

    // Default: allow
    filter.push(bpf_stmt(
        (libc::BPF_RET | libc::BPF_K) as u16,
        libc::SECCOMP_RET_ALLOW,
    ));

    // Deny action
    filter.push(bpf_stmt((libc::BPF_RET | libc::BPF_K) as u16, deny_ret));

    Ok(filter)
}

/// Apply a BPF filter to the current process.
///
/// This sets `PR_SET_NO_NEW_PRIVS` (required for unprivileged seccomp)
/// and then installs the filter via `PR_SET_SECCOMP`.
///
/// # Safety
///
/// Must be called after all setup is complete and right before `execvp`.
/// Once applied, the filter cannot be removed.
pub fn apply_filter(filter: &[libc::sock_filter]) -> Result<(), SeccompError> {
    // PR_SET_NO_NEW_PRIVS is required for unprivileged SECCOMP_MODE_FILTER.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(SeccompError::NoNewPrivs(std::io::Error::last_os_error()));
    }

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &prog as *const libc::sock_fprog,
        )
    };
    if ret != 0 {
        return Err(SeccompError::SetSeccomp(std::io::Error::last_os_error()));
    }

    Ok(())
}

/// Resolve the seccomp profile from the syscall config, apply overrides,
/// and install the BPF filter.
///
/// If the config uses absolute `allow`/`deny` fields (baseline mode),
/// those define the entire policy. If it uses `allow_extra`/`deny_extra`
/// (override mode), the default baseline is resolved from the recipe
/// search path (external file → embedded fallback) and overrides are
/// applied on top.
///
/// This is the main entry point for the sandbox setup path.
pub fn load_and_apply(
    syscall_config: &SyscallConfig,
    action: DenyAction,
) -> Result<(), SeccompError> {
    let profile = if syscall_config.is_baseline() {
        // Absolute mode: the config IS the baseline (e.g., default.toml loaded
        // directly as `--recipe default.toml`). Use its allow/deny as-is.
        SeccompProfile::from_absolute(syscall_config)
    } else {
        // Override mode (or empty): resolve the default baseline, then apply
        // allow_extra / deny_extra on top.
        let resolved = SeccompProfile::resolve_baseline()
            .map_err(|e| SeccompError::BaselineResolution(format!("{e}")))?;

        tracing::debug!(
            source = %resolved.source,
            "resolved seccomp baseline"
        );

        let mut profile = resolved.profile;
        profile.apply_overrides(&syscall_config.allow_extra, &syscall_config.deny_extra);
        profile
    };

    let mode = syscall_config.seccomp_mode();

    let syscall_list = match mode {
        SeccompMode::AllowList => &profile.allow_syscalls,
        SeccompMode::DenyList => &profile.deny_syscalls,
    };

    if syscall_list.is_empty() {
        tracing::debug!(
            %mode,
            "no syscalls for this mode, skipping seccomp"
        );
        return Ok(());
    }

    let filter = build_filter(&profile, action, mode)?;
    tracing::info!(
        instructions = filter.len(),
        syscall_count = syscall_list.len(),
        allow_extra = ?syscall_config.allow_extra,
        deny_extra = ?syscall_config.deny_extra,
        %mode,
        "applying seccomp filter"
    );

    apply_filter(&filter)
}

/// Check whether the kernel supports seccomp filter mode.
pub fn is_supported() -> bool {
    // PR_GET_SECCOMP returns 0 if seccomp is disabled, 2 if filter mode,
    // or -1/EINVAL if not supported at all.
    let ret = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
    // ret >= 0 means seccomp is available (0 = disabled, 2 = filter active).
    // ret == -1 with EINVAL means kernel doesn't support it.
    ret >= 0
}

// --- BPF instruction helpers ---

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

// --- Syscall name to number mapping ---

/// Resolve a list of syscall names to their numeric values.
///
/// Returns an error if any name is unrecognized.
fn resolve_syscall_numbers(names: &[String]) -> Result<Vec<i64>, SeccompError> {
    names.iter().map(|name| syscall_number(name)).collect()
}

/// Map a syscall name to its number on the current architecture.
///
/// This uses `libc::SYS_*` constants which are architecture-specific.
fn syscall_number(name: &str) -> Result<i64, SeccompError> {
    let nr = match name {
        // Process lifecycle
        "fork" => libc::SYS_fork,
        "vfork" => libc::SYS_vfork,
        "clone" => libc::SYS_clone,
        "clone3" => libc::SYS_clone3,
        "execve" => libc::SYS_execve,
        "execveat" => libc::SYS_execveat,
        "kill" => libc::SYS_kill,
        "tkill" => libc::SYS_tkill,
        "tgkill" => libc::SYS_tgkill,
        "exit" => libc::SYS_exit,
        "exit_group" => libc::SYS_exit_group,
        "wait4" => libc::SYS_wait4,
        "waitid" => libc::SYS_waitid,

        // Process control
        "ptrace" => libc::SYS_ptrace,
        "prctl" => libc::SYS_prctl,
        "seccomp" => libc::SYS_seccomp,
        "personality" => libc::SYS_personality,

        // File I/O
        "open" => libc::SYS_open,
        "openat" => libc::SYS_openat,
        "openat2" => libc::SYS_openat2,
        "creat" => libc::SYS_creat,
        "close" => libc::SYS_close,
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "readv" => libc::SYS_readv,
        "writev" => libc::SYS_writev,
        "pread64" => libc::SYS_pread64,
        "pwrite64" => libc::SYS_pwrite64,
        "lseek" => libc::SYS_lseek,
        "dup" => libc::SYS_dup,
        "dup2" => libc::SYS_dup2,
        "dup3" => libc::SYS_dup3,
        "fcntl" => libc::SYS_fcntl,
        "flock" => libc::SYS_flock,
        "fsync" => libc::SYS_fsync,
        "fdatasync" => libc::SYS_fdatasync,
        "truncate" => libc::SYS_truncate,
        "ftruncate" => libc::SYS_ftruncate,

        // File metadata
        "stat" => libc::SYS_stat,
        "fstat" => libc::SYS_fstat,
        "lstat" => libc::SYS_lstat,
        "newfstatat" => libc::SYS_newfstatat,
        "access" => libc::SYS_access,
        "faccessat" => libc::SYS_faccessat,
        "faccessat2" => libc::SYS_faccessat2,
        "chmod" => libc::SYS_chmod,
        "fchmod" => libc::SYS_fchmod,
        "fchmodat" => libc::SYS_fchmodat,
        "chown" => libc::SYS_chown,
        "fchown" => libc::SYS_fchown,
        "lchown" => libc::SYS_lchown,
        "fchownat" => libc::SYS_fchownat,

        // Directory operations
        "mkdir" => libc::SYS_mkdir,
        "mkdirat" => libc::SYS_mkdirat,
        "rmdir" => libc::SYS_rmdir,
        "rename" => libc::SYS_rename,
        "renameat" => libc::SYS_renameat,
        "renameat2" => libc::SYS_renameat2,
        "link" => libc::SYS_link,
        "linkat" => libc::SYS_linkat,
        "unlink" => libc::SYS_unlink,
        "unlinkat" => libc::SYS_unlinkat,
        "symlink" => libc::SYS_symlink,
        "symlinkat" => libc::SYS_symlinkat,
        "readlink" => libc::SYS_readlink,
        "readlinkat" => libc::SYS_readlinkat,
        "getdents" => libc::SYS_getdents,
        "getdents64" => libc::SYS_getdents64,

        // Memory
        "mmap" => libc::SYS_mmap,
        "mprotect" => libc::SYS_mprotect,
        "munmap" => libc::SYS_munmap,
        "mremap" => libc::SYS_mremap,
        "madvise" => libc::SYS_madvise,
        "brk" => libc::SYS_brk,
        "sbrk" => {
            return Err(SeccompError::UnknownSyscall(
                "sbrk (not a syscall)".to_string(),
            ));
        }
        "mlock" => libc::SYS_mlock,
        "mlock2" => libc::SYS_mlock2,
        "munlock" => libc::SYS_munlock,
        "mlockall" => libc::SYS_mlockall,
        "munlockall" => libc::SYS_munlockall,

        // Network
        "socket" => libc::SYS_socket,
        "connect" => libc::SYS_connect,
        "accept" => libc::SYS_accept,
        "accept4" => libc::SYS_accept4,
        "bind" => libc::SYS_bind,
        "listen" => libc::SYS_listen,
        "sendto" => libc::SYS_sendto,
        "recvfrom" => libc::SYS_recvfrom,
        "sendmsg" => libc::SYS_sendmsg,
        "recvmsg" => libc::SYS_recvmsg,
        "shutdown" => libc::SYS_shutdown,
        "getsockopt" => libc::SYS_getsockopt,
        "setsockopt" => libc::SYS_setsockopt,
        "getsockname" => libc::SYS_getsockname,
        "getpeername" => libc::SYS_getpeername,
        "socketpair" => libc::SYS_socketpair,

        // Signals
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "sigaltstack" => libc::SYS_sigaltstack,

        // Time
        "nanosleep" => libc::SYS_nanosleep,
        "clock_nanosleep" => libc::SYS_clock_nanosleep,
        "clock_gettime" => libc::SYS_clock_gettime,
        "clock_getres" => libc::SYS_clock_getres,
        "gettimeofday" => libc::SYS_gettimeofday,
        "settimeofday" => libc::SYS_settimeofday,

        // Polling / async
        "poll" => libc::SYS_poll,
        "ppoll" => libc::SYS_ppoll,
        "select" => libc::SYS_select,
        "pselect6" => libc::SYS_pselect6,
        "epoll_create" => libc::SYS_epoll_create,
        "epoll_create1" => libc::SYS_epoll_create1,
        "epoll_ctl" => libc::SYS_epoll_ctl,
        "epoll_wait" => libc::SYS_epoll_wait,
        "epoll_pwait" => libc::SYS_epoll_pwait,
        "eventfd" => libc::SYS_eventfd,
        "eventfd2" => libc::SYS_eventfd2,
        "timerfd_create" => libc::SYS_timerfd_create,
        "timerfd_settime" => libc::SYS_timerfd_settime,
        "timerfd_gettime" => libc::SYS_timerfd_gettime,

        // IPC
        "pipe" => libc::SYS_pipe,
        "pipe2" => libc::SYS_pipe2,
        "shmget" => libc::SYS_shmget,
        "shmat" => libc::SYS_shmat,
        "shmctl" => libc::SYS_shmctl,
        "shmdt" => libc::SYS_shmdt,
        "semget" => libc::SYS_semget,
        "semop" => libc::SYS_semop,
        "semctl" => libc::SYS_semctl,
        "msgget" => libc::SYS_msgget,
        "msgsnd" => libc::SYS_msgsnd,
        "msgrcv" => libc::SYS_msgrcv,
        "msgctl" => libc::SYS_msgctl,

        // Process info
        "getpid" => libc::SYS_getpid,
        "getppid" => libc::SYS_getppid,
        "getuid" => libc::SYS_getuid,
        "getgid" => libc::SYS_getgid,
        "geteuid" => libc::SYS_geteuid,
        "getegid" => libc::SYS_getegid,
        "gettid" => libc::SYS_gettid,
        "getpgid" => libc::SYS_getpgid,
        "getpgrp" => libc::SYS_getpgrp,
        "setpgid" => libc::SYS_setpgid,
        "setsid" => libc::SYS_setsid,
        "getgroups" => libc::SYS_getgroups,
        "setgroups" => libc::SYS_setgroups,
        "setuid" => libc::SYS_setuid,
        "setgid" => libc::SYS_setgid,
        "setreuid" => libc::SYS_setreuid,
        "setregid" => libc::SYS_setregid,
        "setresuid" => libc::SYS_setresuid,
        "setresgid" => libc::SYS_setresgid,

        // Filesystem (privileged)
        "mount" => libc::SYS_mount,
        "umount2" => libc::SYS_umount2,
        "pivot_root" => libc::SYS_pivot_root,
        "chroot" => libc::SYS_chroot,
        "swapon" => libc::SYS_swapon,
        "swapoff" => libc::SYS_swapoff,

        // Namespace / container
        "unshare" => libc::SYS_unshare,
        "setns" => libc::SYS_setns,

        // System
        "reboot" => libc::SYS_reboot,
        "kexec_load" => libc::SYS_kexec_load,
        "init_module" => libc::SYS_init_module,
        "finit_module" => libc::SYS_finit_module,
        "delete_module" => libc::SYS_delete_module,
        "acct" => libc::SYS_acct,
        "syslog" => libc::SYS_syslog,

        // I/O
        "ioctl" => libc::SYS_ioctl,
        "io_setup" => libc::SYS_io_setup,
        "io_submit" => libc::SYS_io_submit,
        "io_getevents" => libc::SYS_io_getevents,
        "io_destroy" => libc::SYS_io_destroy,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,

        // Misc
        "futex" => libc::SYS_futex,
        "set_tid_address" => libc::SYS_set_tid_address,
        "set_robust_list" => libc::SYS_set_robust_list,
        "get_robust_list" => libc::SYS_get_robust_list,
        "sched_yield" => libc::SYS_sched_yield,
        "sched_getaffinity" => libc::SYS_sched_getaffinity,
        "sched_setaffinity" => libc::SYS_sched_setaffinity,
        "getcwd" => libc::SYS_getcwd,
        "chdir" => libc::SYS_chdir,
        "fchdir" => libc::SYS_fchdir,
        "umask" => libc::SYS_umask,
        "uname" => libc::SYS_uname,
        "sysinfo" => libc::SYS_sysinfo,
        "getrandom" => libc::SYS_getrandom,
        "memfd_create" => libc::SYS_memfd_create,
        "copy_file_range" => libc::SYS_copy_file_range,
        "sendfile" => libc::SYS_sendfile,
        "splice" => libc::SYS_splice,
        "tee" => libc::SYS_tee,

        // Arch-specific
        "arch_prctl" => libc::SYS_arch_prctl,

        _ => return Err(SeccompError::UnknownSyscall(name.to_string())),
    };
    Ok(nr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build default baseline profile (no overrides).
    fn default_profile() -> SeccompProfile {
        SeccompProfile::default_baseline()
    }

    /// Helper: build default profile with overrides applied.
    fn profile_with_overrides(allow_extra: &[&str], deny_extra: &[&str]) -> SeccompProfile {
        let mut profile = SeccompProfile::default_baseline();
        let allow: Vec<String> = allow_extra.iter().map(|s| s.to_string()).collect();
        let deny: Vec<String> = deny_extra.iter().map(|s| s.to_string()).collect();
        profile.apply_overrides(&allow, &deny);
        profile
    }

    // --- Deny-list mode tests ---

    #[test]
    fn deny_list_filter_for_default_baseline() {
        let profile = default_profile();
        let n_denied = profile.deny_syscalls.len();
        let filter =
            build_filter(&profile, DenyAction::KillProcess, SeccompMode::DenyList).unwrap();

        // Structure: 3 (arch) + 1 (load nr) + N (checks) + 1 (allow) + 1 (deny)
        let expected_len = 3 + 1 + n_denied + 1 + 1;
        assert_eq!(filter.len(), expected_len, "unexpected filter length");
        assert!(
            n_denied >= 14,
            "default baseline should deny at least the always-deny set"
        );
    }

    #[test]
    fn deny_list_with_extra_denies() {
        let base = default_profile();
        let base_denied = base.deny_syscalls.len();

        let profile = profile_with_overrides(&[], &["ptrace", "personality"]);
        assert_eq!(
            profile.deny_syscalls.len(),
            base_denied + 2,
            "deny_extra should add to deny list"
        );
    }

    #[test]
    fn deny_list_empty_returns_error() {
        let profile = SeccompProfile {
            name: "empty".to_string(),
            description: "no denies".to_string(),
            allow_syscalls: vec![],
            deny_syscalls: vec![],
        };
        let result = build_filter(&profile, DenyAction::KillProcess, SeccompMode::DenyList);
        assert!(matches!(result, Err(SeccompError::EmptyFilter)));
    }

    #[test]
    fn deny_list_unknown_syscall_returns_error() {
        let profile = SeccompProfile {
            name: "bad".to_string(),
            description: "has unknown".to_string(),
            allow_syscalls: vec![],
            deny_syscalls: vec!["totally_fake_syscall".to_string()],
        };
        let result = build_filter(&profile, DenyAction::KillProcess, SeccompMode::DenyList);
        assert!(matches!(result, Err(SeccompError::UnknownSyscall(_))));
    }

    #[test]
    fn deny_list_filter_starts_with_arch_check() {
        let profile = default_profile();
        let filter =
            build_filter(&profile, DenyAction::KillProcess, SeccompMode::DenyList).unwrap();

        assert_eq!(
            filter[0].code,
            (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16
        );
        assert_eq!(filter[0].k, OFFSET_ARCH);
        assert_eq!(
            filter[1].code,
            (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16
        );
        assert_eq!(filter[1].k, AUDIT_ARCH_NATIVE);
    }

    #[test]
    fn deny_list_ends_with_deny_action() {
        let profile = default_profile();
        let filter =
            build_filter(&profile, DenyAction::KillProcess, SeccompMode::DenyList).unwrap();

        // Deny-list layout: [...checks...] [ALLOW] [DENY]
        let last = filter.last().unwrap();
        assert_eq!(last.code, (libc::BPF_RET | libc::BPF_K) as u16);
        assert_eq!(last.k, libc::SECCOMP_RET_KILL_PROCESS);

        let allow = &filter[filter.len() - 2];
        assert_eq!(allow.code, (libc::BPF_RET | libc::BPF_K) as u16);
        assert_eq!(allow.k, libc::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn deny_list_kill_uses_correct_return() {
        let profile = default_profile();
        let filter =
            build_filter(&profile, DenyAction::KillProcess, SeccompMode::DenyList).unwrap();

        let deny = filter.last().unwrap();
        assert_eq!(deny.k, libc::SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn deny_list_errno_uses_eperm() {
        let profile = default_profile();
        let filter = build_filter(&profile, DenyAction::Errno, SeccompMode::DenyList).unwrap();

        let deny = filter.last().unwrap();
        assert_eq!(deny.k, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);
    }

    #[test]
    fn deny_list_log_uses_ret_log() {
        let profile = default_profile();
        let filter = build_filter(&profile, DenyAction::Log, SeccompMode::DenyList).unwrap();

        let deny = filter.last().unwrap();
        assert_eq!(deny.k, SECCOMP_RET_LOG);
    }

    #[test]
    fn deny_list_jump_offsets_are_correct() {
        let profile = SeccompProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            allow_syscalls: vec![],
            deny_syscalls: vec![
                "reboot".to_string(),
                "mount".to_string(),
                "ptrace".to_string(),
            ],
        };
        let filter =
            build_filter(&profile, DenyAction::KillProcess, SeccompMode::DenyList).unwrap();

        // [load_arch, cmp_arch, kill_arch, load_nr, cmp0, cmp1, cmp2, allow_ret, deny_ret]
        assert_eq!(filter[4].jt, 3); // skip cmp1, cmp2, allow → deny_ret
        assert_eq!(filter[4].jf, 0);
        assert_eq!(filter[5].jt, 2);
        assert_eq!(filter[5].jf, 0);
        assert_eq!(filter[6].jt, 1);
        assert_eq!(filter[6].jf, 0);
    }

    // --- Allow-list mode tests ---

    #[test]
    fn allow_list_filter_for_default_baseline() {
        let profile = default_profile();
        let n_allowed = profile.allow_syscalls.len();
        let filter =
            build_filter(&profile, DenyAction::KillProcess, SeccompMode::AllowList).unwrap();

        // Structure: 3 (arch) + 1 (load nr) + N (checks) + 1 (deny) + 1 (allow)
        let expected_len = 3 + 1 + n_allowed + 1 + 1;
        assert_eq!(filter.len(), expected_len, "unexpected filter length");
        assert!(
            n_allowed > 100,
            "default allow-list should have >100 syscalls, got {n_allowed}"
        );
    }

    #[test]
    fn allow_list_default_action_is_deny() {
        let profile = default_profile();
        let filter =
            build_filter(&profile, DenyAction::KillProcess, SeccompMode::AllowList).unwrap();

        // Allow-list layout: [...checks...] [DENY] [ALLOW]
        // Second-to-last is deny (default), last is allow (matched).
        let deny = &filter[filter.len() - 2];
        assert_eq!(deny.code, (libc::BPF_RET | libc::BPF_K) as u16);
        assert_eq!(deny.k, libc::SECCOMP_RET_KILL_PROCESS);

        let allow = filter.last().unwrap();
        assert_eq!(allow.code, (libc::BPF_RET | libc::BPF_K) as u16);
        assert_eq!(allow.k, libc::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn allow_list_errno_as_default_deny() {
        let profile = default_profile();
        let filter = build_filter(&profile, DenyAction::Errno, SeccompMode::AllowList).unwrap();

        let deny = &filter[filter.len() - 2];
        assert_eq!(deny.k, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);
    }

    #[test]
    fn allow_list_empty_returns_error() {
        let profile = SeccompProfile {
            name: "empty".to_string(),
            description: "no allows".to_string(),
            allow_syscalls: vec![],
            deny_syscalls: vec!["reboot".to_string()],
        };
        let result = build_filter(&profile, DenyAction::KillProcess, SeccompMode::AllowList);
        assert!(matches!(result, Err(SeccompError::EmptyFilter)));
    }

    #[test]
    fn allow_list_jump_offsets_are_correct() {
        let profile = SeccompProfile {
            name: "test".to_string(),
            description: "test".to_string(),
            allow_syscalls: vec![
                "read".to_string(),
                "write".to_string(),
                "exit_group".to_string(),
            ],
            deny_syscalls: vec![],
        };
        let filter =
            build_filter(&profile, DenyAction::KillProcess, SeccompMode::AllowList).unwrap();

        // [load_arch, cmp_arch, kill_arch, load_nr, cmp0, cmp1, cmp2, deny_ret, allow_ret]
        // cmp0 (index 4): if read matches → skip cmp1, cmp2, deny → allow_ret
        assert_eq!(filter[4].jt, 3);
        assert_eq!(filter[4].jf, 0);
        // cmp1 (index 5): if write matches → skip cmp2, deny → allow_ret
        assert_eq!(filter[5].jt, 2);
        assert_eq!(filter[5].jf, 0);
        // cmp2 (index 6): if exit_group matches → skip deny → allow_ret
        assert_eq!(filter[6].jt, 1);
        assert_eq!(filter[6].jf, 0);
    }

    #[test]
    fn allow_list_no_overlap_with_deny_always() {
        // Verify that the default baseline's allow list contains no always-denied syscalls.
        let deny_always: Vec<&str> = vec![
            "reboot",
            "kexec_load",
            "init_module",
            "finit_module",
            "delete_module",
            "swapon",
            "swapoff",
            "acct",
            "mount",
            "umount2",
            "pivot_root",
            "chroot",
            "syslog",
            "settimeofday",
            "unshare",
            "setns",
        ];
        let profile = default_profile();
        for syscall in &profile.allow_syscalls {
            assert!(
                !deny_always.contains(&syscall.as_str()),
                "default allow-list contains DENY_ALWAYS syscall: {syscall}"
            );
        }
    }

    #[test]
    fn allow_list_default_baseline_compiles() {
        let profile = default_profile();
        let filter = build_filter(&profile, DenyAction::KillProcess, SeccompMode::AllowList);
        assert!(
            filter.is_ok(),
            "default baseline failed to compile in allow-list mode: {:?}",
            filter.err()
        );
    }

    #[test]
    fn deny_list_default_baseline_compiles() {
        let profile = default_profile();
        let filter = build_filter(&profile, DenyAction::KillProcess, SeccompMode::DenyList);
        assert!(
            filter.is_ok(),
            "default baseline failed to compile in deny-list mode: {:?}",
            filter.err()
        );
    }

    // --- Override tests ---

    #[test]
    fn allow_extra_adds_to_allow_list() {
        let base = default_profile();
        let base_count = base.allow_syscalls.len();

        let profile = profile_with_overrides(&["ptrace", "io_uring_setup"], &[]);
        assert_eq!(profile.allow_syscalls.len(), base_count + 2);
        assert!(profile.allow_syscalls.contains(&"ptrace".to_string()));
        assert!(
            profile
                .allow_syscalls
                .contains(&"io_uring_setup".to_string())
        );
    }

    #[test]
    fn deny_extra_removes_from_allow_and_adds_to_deny() {
        // "read" is in the default allow list
        let profile = profile_with_overrides(&[], &["read"]);
        assert!(
            !profile.allow_syscalls.contains(&"read".to_string()),
            "deny_extra should remove from allow list"
        );
        assert!(
            profile.deny_syscalls.contains(&"read".to_string()),
            "deny_extra should add to deny list"
        );
    }

    #[test]
    fn allow_extra_deduplicates() {
        // "read" is already in the default allow list
        let base = default_profile();
        let base_count = base.allow_syscalls.len();

        let profile = profile_with_overrides(&["read"], &[]);
        assert_eq!(
            profile.allow_syscalls.len(),
            base_count,
            "duplicate should not increase count"
        );
    }

    #[test]
    fn deny_extra_already_denied_deduplicates() {
        // "reboot" is already in DENY_ALWAYS
        let base = default_profile();
        let base_deny_count = base.deny_syscalls.len();

        let profile = profile_with_overrides(&[], &["reboot"]);
        assert_eq!(
            profile.deny_syscalls.len(),
            base_deny_count,
            "duplicate deny should not increase count"
        );
    }

    #[test]
    fn allow_extra_with_overrides_compiles() {
        let profile = profile_with_overrides(
            &[
                "ptrace",
                "io_uring_setup",
                "io_uring_enter",
                "io_uring_register",
            ],
            &[],
        );
        let filter = build_filter(&profile, DenyAction::KillProcess, SeccompMode::AllowList);
        assert!(filter.is_ok());
    }

    // --- Common tests ---

    #[test]
    fn syscall_number_known_syscalls() {
        assert_eq!(syscall_number("read").unwrap(), 0);
        assert_eq!(syscall_number("write").unwrap(), 1);
        assert_eq!(syscall_number("execve").unwrap(), 59);
        assert_eq!(syscall_number("reboot").unwrap(), 169);
    }

    #[test]
    fn syscall_number_rejects_unknown() {
        assert!(syscall_number("not_a_real_syscall").is_err());
    }

    #[test]
    fn is_supported_returns_bool() {
        let _ = is_supported();
    }
}
