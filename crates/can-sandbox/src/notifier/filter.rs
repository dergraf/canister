//! BPF filter installation for `SECCOMP_RET_USER_NOTIF`.
//!
//! The filter built here is a small allow/deny prelude that returns
//! `SECCOMP_RET_USER_NOTIF` for a fixed set of syscalls and
//! `SECCOMP_RET_ALLOW` for everything else. It is installed *before* the
//! main allow/deny filter: seccomp evaluates filters in reverse install
//! order, so this filter runs first.

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use super::abi::{
    SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_RET_USER_NOTIF, SECCOMP_SET_MODE_FILTER,
};
use super::error::NotifierError;

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

/// Build a BPF filter that returns `SECCOMP_RET_USER_NOTIF` for the
/// notified syscalls and `SECCOMP_RET_ALLOW` for everything else.
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

/// Install the USER_NOTIF filter and return the notification fd.
///
/// Must be called from the child process after `PR_SET_NO_NEW_PRIVS` is
/// set. The returned fd is the "listener" end — send it to the
/// supervisor via the fd channel before `exec()`.
pub fn install_notifier_filter() -> Result<OwnedFd, NotifierError> {
    // PR_SET_NO_NEW_PRIVS is required for unprivileged seccomp.
    // Idempotent — safe even if already set by the main seccomp filter.
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

    let fd = unsafe { OwnedFd::from_raw_fd(ret as RawFd) };
    tracing::debug!(fd = ret, "installed USER_NOTIF filter, got notifier fd");
    Ok(fd)
}
