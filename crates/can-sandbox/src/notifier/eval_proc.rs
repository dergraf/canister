//! `execve()` / `execveat()` path evaluators — the per-exec path
//! allow-list check, and the **only** remaining USER_NOTIF check that
//! reads the worker's memory. The `socket()` resource gate and
//! `clone`/`clone3` namespace-flag gates now live in the static BPF
//! prelude (`filter.rs`); egress is enforced by the network topology.
//!
//! # The residual TOCTOU here is intentional, and bounded
//!
//! These evaluators read the pathname from `/proc/<pid>/mem` and then
//! answer `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (see `supervisor.rs`). The
//! kernel *re-reads* the pathname pointer when it actually runs the
//! `execve`, so a sibling `CLONE_VM` thread can swap the path in the
//! check-to-execute window (the classic seccomp-unotify race;
//! `is_notif_id_valid` narrows but does not close it). We knowingly keep
//! this because the bypass it enables is a **policy bypass, not an escape
//! or escalation**:
//!
//! 1. The race only changes *which path the kernel resolves* — it cannot
//!    conjure a binary. The path must resolve to a real executable in the
//!    worker's post-`pivot_root` mount namespace, i.e. something the
//!    recipe author bind-mounted read-only. Writable areas (CWD, /tmp,
//!    writable binds, the root tmpfs) are mounted `noexec` whenever an
//!    exec allow-list is in force (see the invariant below), so a dropped
//!    payload cannot be race-exec'd.
//! 2. `execve` preserves every confinement layer: `NO_NEW_PRIVS` (so
//!    setuid bits / file caps are ignored), the seccomp filters, the
//!    empty capability sets, the user/PID/mount/net namespaces, cgroups,
//!    and rlimits all persist unchanged. A raced binary runs with
//!    *identical* privilege and reach to the one it impersonated.
//! 3. It therefore gains no escape primitive: no namespace creation
//!    (static BPF + baseline deny), no direct network (no uplink in proxy
//!    mode), no raw sockets, no remount. `memfd`/`AT_EMPTY_PATH` exec is
//!    independently denied. The *initial* command is validated race-free
//!    in the parent (`process::validate_execve`).
//!
//! ## Load-bearing invariant
//!
//! The supervisor only enforces a non-trivial allow-list when
//! `process.exec()` is `Allow(paths)`, and in exactly that case
//! `overlay.rs` mounts writable areas `noexec` (`exec_restricted`). So in
//! every configuration where this race could defeat the allow-list, the
//! worker also cannot introduce a new executable — the race can at most
//! pick a different recipe-provided, read-only binary, which then runs
//! fully confined. `allow_execve` is thus a best-effort hardening control,
//! **not** a privilege/escape boundary. See `docs/ARCHITECTURE.md` §4b.
//! If this invariant is ever weakened (e.g. an exec allow-list with an
//! exec-mounted writable path), this analysis no longer holds.

use std::os::fd::RawFd;
use std::path::{Path, PathBuf};

use super::abi::SeccompNotif;
use super::policy::NotifierPolicy;
use super::proc_mem::read_proc_string_with_retry;
use super::supervisor::{Verdict, is_notif_id_valid};

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
