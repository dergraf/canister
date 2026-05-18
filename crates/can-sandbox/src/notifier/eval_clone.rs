//! `clone()` / `clone3()` evaluators — refuse any namespace-creating
//! flag so the worker can't escape its sandbox by spawning a child in
//! a fresh namespace.

use std::os::fd::RawFd;

use super::abi::{NS_FLAGS_MASK, SeccompNotif};
use super::proc_mem::read_proc_mem;
use super::supervisor::{Verdict, is_notif_id_valid};

/// Evaluate a `clone()` syscall.
///
/// `clone(flags, ...)`: `args[0]` = clone flags.
pub(super) fn evaluate_clone(args: &[u64; 6], pid: u32) -> Verdict {
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
/// `clone3(struct clone_args *args, size_t size)`:
///   args[0] = pointer to struct clone_args (first u64 is `flags`)
///   args[1] = size
pub(super) fn evaluate_clone3(notif: &SeccompNotif, notifier_fd: RawFd) -> Verdict {
    let pid = notif.pid;
    let args_ptr = notif.data.args[0];
    let args_size = notif.data.args[1] as usize;

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

    if !is_notif_id_valid(notifier_fd, notif.id) {
        tracing::debug!(pid, "clone3: notification invalidated (TOCTOU)");
        return Verdict::Deny(libc::EPERM as u32);
    }

    // SAFETY-UNWRAP: flags_bytes was just read as exactly 8 bytes; the
    // try_into to [u8; 8] cannot fail.
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
