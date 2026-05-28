//! `execve()` / `execveat()` path evaluators — the per-exec path
//! allow-list check. Distinct from eval_net (per-call destinations). The
//! `socket()` resource gate and `clone`/`clone3` namespace-flag gates now
//! live in the static BPF prelude (`filter.rs`) and never reach here.

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
