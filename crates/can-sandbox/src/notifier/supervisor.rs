//! The supervisor loop: poll the notifier fd, read each notification,
//! dispatch to the right evaluator, and write the verdict back.
//!
//! Runs as PID 1 in the sandbox's PID namespace. Single-threaded —
//! `clone(CLONE_THREAD)` returns EINVAL after `unshare(CLONE_NEWPID)`.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};

use super::abi::{
    SECCOMP_IOCTL_NOTIF_ID_VALID, SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND,
    SECCOMP_USER_NOTIF_FLAG_CONTINUE, SeccompNotif, SeccompNotifResp,
};
use super::eval_clone::{evaluate_clone, evaluate_clone3};
use super::eval_net::{evaluate_connect, evaluate_sendmsg, evaluate_sendto};
use super::eval_proc::{evaluate_execve, evaluate_execveat, evaluate_socket};
use super::policy::NotifierPolicy;

/// Verdict from evaluating a syscall notification. `pub(super)` so each
/// per-syscall evaluator can construct one.
#[derive(Debug)]
pub(super) enum Verdict {
    /// Allow the syscall to proceed.
    Allow,
    /// Deny the syscall with the given errno.
    Deny(u32),
}

/// Flag set by the SIGTERM/SIGINT handler to request supervisor
/// shutdown. PID 1 in a PID namespace silently ignores signals without
/// handlers, so we must install an explicit handler.
static SUPERVISOR_SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn supervisor_signal_handler(_sig: libc::c_int) {
    SUPERVISOR_SHUTDOWN.store(true, Ordering::Release);
}

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

/// Run the seccomp supervisor loop, processing notifications and
/// monitoring the child process.
///
/// After `unshare(CLONE_NEWPID)`, the intermediate process cannot spawn
/// threads (`clone(CLONE_THREAD)` returns `EINVAL` when
/// `pid_ns_for_children != task_active_pid_ns`). This function runs the
/// supervisor loop directly in the calling process, interleaving
/// seccomp notification handling with non-blocking `waitpid` checks on
/// the child. Returns the exit code to use for `process::exit()`.
pub fn run_supervisor_with_child(
    notifier_fd: OwnedFd,
    policy: &NotifierPolicy,
    child: nix::unistd::Pid,
) -> i32 {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};

    install_supervisor_signal_handler();

    let fd = notifier_fd.as_raw_fd();
    let mut child_exit_code: Option<i32> = None;

    loop {
        if SUPERVISOR_SHUTDOWN.load(Ordering::Acquire) {
            tracing::info!("supervisor received shutdown signal, killing worker");
            let _ = nix::sys::signal::kill(child, nix::sys::signal::SIGKILL);
            // Fall through to waitpid to collect the child's exit status.
        }

        // Non-blocking child status check.
        match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => {
                tracing::debug!(code, "inner child exited");
                child_exit_code = Some(code);
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
            Ok(WaitStatus::StillAlive) => {}
            Ok(_) => {}
            Err(nix::Error::ECHILD) => {
                tracing::debug!("inner child already reaped");
                child_exit_code = Some(1);
                break;
            }
            Err(nix::Error::EINTR) => continue,
            Err(e) => {
                tracing::error!(error = %e, "waitpid failed");
                child_exit_code = Some(1);
                break;
            }
        }

        // Poll for an incoming notification, with a 200ms timeout so we
        // periodically re-check child status / shutdown flag.
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
            continue;
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            tracing::debug!(
                revents = pfd.revents,
                "notifier fd closed/error, stopping supervisor"
            );
            break;
        }

        process_one_notification(fd, policy);
    }

    let code = child_exit_code.unwrap_or_else(|| match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, code)) => code,
        Ok(WaitStatus::Signaled(_, signal, _)) => 128 + signal as i32,
        _ => 1,
    });

    drop(notifier_fd);
    tracing::debug!(code, "seccomp supervisor exiting");
    code
}

/// Drain any pending notifications after the child has exited.
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

/// Dispatch a notification to the appropriate per-syscall evaluator.
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

/// TOCTOU guard: confirm the notification is still active before
/// committing a verdict that depended on reading the worker's memory.
pub(super) fn is_notif_id_valid(notifier_fd: RawFd, id: u64) -> bool {
    let ret = unsafe {
        libc::ioctl(
            notifier_fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID as _,
            &id as *const _,
        )
    };
    ret == 0
}
