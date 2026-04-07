use std::ffi::CString;
use std::io::{Read as _, Write as _};

use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork, pipe};

use crate::{SandboxOpts, resolve_command, to_cstring};

/// Errors specific to namespace operations.
#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error("unshare failed: {0}")]
    Unshare(nix::Error),

    #[error("fork failed: {0}")]
    Fork(nix::Error),

    #[error("execve failed: {0}")]
    Exec(nix::Error),

    #[error("waitpid failed: {0}")]
    Wait(nix::Error),

    #[error("uid/gid map write failed: {0}")]
    UidMap(std::io::Error),
}

/// Spawn a process inside new namespaces.
///
/// The protocol between parent and child:
/// 1. Parent forks
/// 2. Child calls `unshare()` to enter new namespaces
/// 3. Child signals parent via pipe that it's ready
/// 4. Parent writes UID/GID maps for the child
/// 5. Parent signals child via pipe that maps are written
/// 6. Child proceeds with setup and exec
pub fn spawn_sandboxed(opts: &SandboxOpts) -> Result<i32, NamespaceError> {
    let command_path =
        resolve_command(&opts.command).map_err(|_| NamespaceError::Exec(nix::Error::ENOENT))?;

    let cmd = to_cstring(command_path.to_str().unwrap_or(&opts.command))
        .map_err(|_| NamespaceError::Exec(nix::Error::EINVAL))?;

    let mut argv: Vec<CString> = vec![cmd.clone()];
    for arg in &opts.args {
        argv.push(
            CString::new(arg.as_bytes()).map_err(|_| NamespaceError::Exec(nix::Error::EINVAL))?,
        );
    }

    let clone_flags =
        CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;

    // Create two pipes for parent-child synchronization.
    // child_ready: child writes after unshare, parent reads to know child is ready.
    // parent_done: parent writes after UID/GID maps, child reads to know it can proceed.
    let child_ready = pipe().map_err(NamespaceError::Fork)?;
    let parent_done = pipe().map_err(NamespaceError::Fork)?;

    // Capture UID/GID before fork (same in parent and child pre-unshare).
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();

    tracing::debug!(?clone_flags, %uid, %gid, "creating namespaces");

    // SAFETY: fork is unsafe in multi-threaded programs. We call it
    // early before spawning any threads.
    let fork_result = unsafe { fork() }.map_err(NamespaceError::Fork)?;

    match fork_result {
        ForkResult::Parent { child } => {
            // Close write end of child_ready and read end of parent_done.
            drop(child_ready.1);
            drop(parent_done.0);

            // Wait for child to signal it has called unshare().
            let mut buf = [0u8; 1];
            let mut ready_r = std::fs::File::from(child_ready.0);
            ready_r
                .read_exact(&mut buf)
                .map_err(NamespaceError::UidMap)?;

            tracing::debug!(
                child_pid = child.as_raw(),
                "child ready, writing uid/gid maps"
            );

            // Write UID/GID mappings from the parent (which has permission).
            write_uid_gid_maps(child, uid, gid)?;

            // Signal child that maps are written.
            let mut done_w = std::fs::File::from(parent_done.1);
            done_w.write_all(&[0u8]).map_err(NamespaceError::UidMap)?;
            drop(done_w);

            wait_for_child(child)
        }
        ForkResult::Child => {
            // Close read end of child_ready and write end of parent_done.
            drop(child_ready.0);
            drop(parent_done.1);

            let result = child_entry(clone_flags, &cmd, &argv, child_ready.1, parent_done.0);
            match result {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("canister: sandbox setup failed: {e}");
                    std::process::exit(126);
                }
            }
        }
    }
}

/// Child process: unshare, sync with parent, then exec.
fn child_entry(
    flags: CloneFlags,
    cmd: &CString,
    argv: &[CString],
    ready_write: std::os::fd::OwnedFd,
    done_read: std::os::fd::OwnedFd,
) -> Result<(), NamespaceError> {
    // Unshare into new namespaces.
    unshare(flags).map_err(NamespaceError::Unshare)?;

    // Signal parent that unshare is complete.
    let mut ready_w = std::fs::File::from(ready_write);
    ready_w.write_all(&[0u8]).map_err(NamespaceError::UidMap)?;
    drop(ready_w);

    // Wait for parent to write UID/GID maps.
    let mut buf = [0u8; 1];
    let mut done_r = std::fs::File::from(done_read);
    done_r
        .read_exact(&mut buf)
        .map_err(NamespaceError::UidMap)?;
    drop(done_r);

    tracing::debug!("namespaces created, uid/gid mapped, executing target");

    // Phase 2: overlay FS setup will go here.
    // Phase 3: network namespace + DNS proxy will go here.
    // Phase 4: seccomp filter will be loaded here (last, before exec).

    // Exec the target command.
    nix::unistd::execvp(cmd, argv).map_err(NamespaceError::Exec)?;

    unreachable!()
}

/// Write UID/GID mappings for a child process from the parent.
fn write_uid_gid_maps(
    child: Pid,
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
) -> Result<(), NamespaceError> {
    let pid = child.as_raw();

    // Deny setgroups first (required before writing gid_map as unprivileged user).
    std::fs::write(format!("/proc/{pid}/setgroups"), "deny").map_err(NamespaceError::UidMap)?;

    // Map host UID -> root (0) inside the namespace.
    std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1"))
        .map_err(NamespaceError::UidMap)?;

    // Map host GID -> root (0) inside the namespace.
    std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1"))
        .map_err(NamespaceError::UidMap)?;

    Ok(())
}

/// Parent process: wait for the sandboxed child.
fn wait_for_child(child: Pid) -> Result<i32, NamespaceError> {
    tracing::debug!(pid = child.as_raw(), "waiting for sandboxed process");

    loop {
        match waitpid(child, None).map_err(NamespaceError::Wait)? {
            WaitStatus::Exited(_, code) => return Ok(code),
            WaitStatus::Signaled(_, signal, _) => {
                tracing::warn!(%signal, "sandboxed process killed by signal");
                return Ok(128 + signal as i32);
            }
            _ => continue,
        }
    }
}
