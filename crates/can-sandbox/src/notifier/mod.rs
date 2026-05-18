//! `SECCOMP_RET_USER_NOTIF` supervisor for argument-level syscall
//! filtering.
//!
//! When the kernel encounters a syscall matching a USER_NOTIF filter,
//! it suspends the calling thread and sends a notification to a
//! supervisor (this module) via a file descriptor. The supervisor
//! reads the syscall arguments, inspects them (e.g., reading memory
//! from `/proc/<pid>/mem`), and sends a verdict (allow or deny).
//!
//! # Architecture
//!
//! The supervisor runs as PID 1 inside the sandbox's PID namespace,
//! not as a thread in the parent. This is necessary because:
//!
//! 1. After `unshare(CLONE_NEWPID)`, `clone(CLONE_THREAD)` returns
//!    `EINVAL` (`pid_ns_for_children != task_active_pid_ns`), so we
//!    cannot spawn a supervisor thread.
//! 2. The host's procfs (`s_user_ns = init_user_ns`) denies
//!    `/proc/<pid>/mem` opens from a child user namespace, so the
//!    supervisor must mount its own procfs in the sandbox's
//!    user/PID namespace.
//! 3. PID 1 is an ancestor of all sandboxed processes, satisfying
//!    Yama `ptrace_scope=1` without `PR_SET_PTRACER`.
//!
//! ```text
//!   PID 1 (supervisor)                   PID 2+ (worker / sandboxed)
//!   ──────────────────                   ────────────────────────────
//!   1. unshare(CLONE_NEWNS)              1. Sandbox setup (overlay, pivot_root)
//!   2. mount /proc (owned by user ns)    2. Install USER_NOTIF filter
//!   3. Receive notifier fd via pipe      3. Send notifier fd to PID 1
//!      + pidfd_getfd                        via pipe
//!   4. Loop: poll(notifier_fd, 200ms)    4. exec target command
//!            read notification
//!            inspect via /proc/<pid>/mem
//!            send ALLOW or DENY verdict
//!            waitpid(WNOHANG) for child
//! ```
//!
//! # Requirements
//!
//! - Linux 5.9+ (for `SECCOMP_IOCTL_NOTIF_RECV`, `_SEND`,
//!   `SECCOMP_ADDFD_FLAG_SEND`).
//! - `PR_SET_NO_NEW_PRIVS` on the worker (set by the regular filter).
//!   The supervisor itself must NOT have `PR_SET_NO_NEW_PRIVS` set,
//!   or `/proc/<pid>/mem` access breaks.
//!
//! # Module layout
//!
//! Splitting from the original ~3175-line `notifier.rs`:
//! - `abi` — kernel ABI constants + ioctl-facing structs.
//! - `error` — `NotifierError`.
//! - `policy` — `NotifierPolicy` (runtime state).
//! - `policy_config` — `policy_from_config`: builds a `NotifierPolicy`
//!   from a `SandboxConfig`.
//! - `kernel` — kernel-version detection (`is_notifier_supported`).
//! - `filter` — BPF filter construction + installation.
//! - `fd_channel` — pipe + `pidfd_getfd()` fd passing.
//! - `supervisor` — main loop, signal handler, notification dispatch,
//!   TOCTOU validity check.
//! - `proc_mem` — `/proc/<pid>/mem` and `process_vm_readv(2)` helpers.
//! - `outbound` — shared IP classification + CIDR matching.
//! - `eval_net` — `connect` / `sendto` / `sendmsg` evaluators + their
//!   pure `classify_*` helpers + DNS allowlist refresh.
//! - `eval_clone` — `clone` / `clone3` evaluators.
//! - `eval_proc` — `socket` / `execve` / `execveat` evaluators.
//! - `tests` — the test suite.

mod abi;
mod error;
mod eval_clone;
mod eval_net;
mod eval_proc;
mod fd_channel;
mod filter;
mod kernel;
mod outbound;
mod policy;
mod policy_config;
mod proc_mem;
mod supervisor;

pub use error::NotifierError;
pub use fd_channel::{create_fd_channel, recv_fd, send_fd};
pub use filter::{NOTIFIED_SYSCALLS, build_notifier_filter, install_notifier_filter};
pub use kernel::is_notifier_supported;
pub use policy::NotifierPolicy;
pub use policy_config::policy_from_config;
pub use supervisor::run_supervisor_with_child;

#[cfg(test)]
mod tests;
