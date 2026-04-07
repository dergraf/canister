use std::ffi::CString;
use std::io::{Read as _, Write as _};
use std::path::Path;

use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork, pipe};

use can_net::{NetworkMode, NetworkState};
use can_policy::SandboxConfig;

use crate::{SandboxOpts, overlay, process, resolve_command, seccomp, to_cstring};

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

    #[error("filesystem setup failed: {0}")]
    Overlay(#[from] overlay::OverlayError),

    #[error("network setup failed: {0}")]
    Network(#[from] can_net::NetError),

    #[error("seccomp filter failed: {0}")]
    Seccomp(#[from] seccomp::SeccompError),

    #[error("process control failed: {0}")]
    Process(#[from] crate::process::ProcessError),
}

/// Spawn a process inside new namespaces.
///
/// The protocol between parent and child:
/// 1. Parent validates command against `allow_execve` whitelist
/// 2. Parent forks
/// 3. Child calls `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID [| CLONE_NEWNET])` atomically
/// 4. Child signals parent via pipe that namespaces are created
/// 5. Parent writes UID/GID maps for the child
/// 6. Parent optionally starts slirp4netns for filtered network mode
/// 7. Parent signals child via pipe that maps (and network) are ready
/// 8. Child forks again for PID namespace (inner child becomes PID 1)
/// 9. PID-1 child sets up filesystem, network, RLIMIT_NPROC, seccomp, env filtering
/// 10. PID-1 child execs the target command with filtered environment
pub fn spawn_sandboxed(opts: &SandboxOpts) -> Result<i32, NamespaceError> {
    let command_path =
        resolve_command(&opts.command).map_err(|_| NamespaceError::Exec(nix::Error::ENOENT))?;

    // Validate the command against the allow_execve whitelist before forking.
    // In monitor mode, log the violation but allow it through.
    if opts.monitor {
        if let Err(e) = process::validate_execve(&command_path, &opts.config.process) {
            tracing::warn!(
                command = %command_path.display(),
                error = %e,
                "MONITOR: command would be blocked by allow_execve policy"
            );
        }
    } else {
        process::validate_execve(&command_path, &opts.config.process)?;
    }

    let cmd = to_cstring(command_path.to_str().unwrap_or(&opts.command))
        .map_err(|_| NamespaceError::Exec(nix::Error::EINVAL))?;

    let mut argv: Vec<CString> = vec![cmd.clone()];
    for arg in &opts.args {
        argv.push(
            CString::new(arg.as_bytes()).map_err(|_| NamespaceError::Exec(nix::Error::EINVAL))?,
        );
    }

    // Determine network isolation mode from policy.
    let net_mode = NetworkMode::from_config(&opts.config.network);
    tracing::debug!(?net_mode, "network isolation mode");

    // Create two pipes for parent-child synchronization.
    let child_ready = pipe().map_err(NamespaceError::Fork)?;
    let parent_done = pipe().map_err(NamespaceError::Fork)?;

    // Capture UID/GID before fork.
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();

    tracing::debug!(%uid, %gid, "forking for sandbox");

    // SAFETY: fork is unsafe in multi-threaded programs. We call it
    // early before spawning any threads.
    let fork_result = unsafe { fork() }.map_err(NamespaceError::Fork)?;

    match fork_result {
        ForkResult::Parent { child } => {
            drop(child_ready.1);
            drop(parent_done.0);

            // Wait for child to signal that namespaces are created.
            let mut buf = [0u8; 1];
            let mut ready_r = std::fs::File::from(child_ready.0);
            ready_r
                .read_exact(&mut buf)
                .map_err(NamespaceError::UidMap)?;

            tracing::debug!(
                child_pid = child.as_raw(),
                "child ready, writing uid/gid maps"
            );

            // Write UID/GID mappings from the parent.
            write_uid_gid_maps(child, uid, gid)?;

            // Set up network infrastructure from the parent side.
            let mut net_state = NetworkState::new();
            if net_mode == NetworkMode::Filtered {
                match setup_parent_network(child, &opts.config, &mut net_state) {
                    Ok(()) => tracing::debug!("parent network setup complete"),
                    Err(e) => {
                        tracing::warn!(error = %e, "parent network setup failed, child will run without filtered network");
                        // Don't fail hard — child will detect missing network
                    }
                }
            }

            // Signal child that maps (and network) are written.
            let mut done_w = std::fs::File::from(parent_done.1);
            done_w.write_all(&[0u8]).map_err(NamespaceError::UidMap)?;
            drop(done_w);

            let result = wait_for_child(child);

            // Clean up network infrastructure.
            net_state.shutdown();

            result
        }
        ForkResult::Child => {
            drop(child_ready.0);
            drop(parent_done.1);

            let result = child_entry(
                &cmd,
                &argv,
                &command_path,
                child_ready.1,
                parent_done.0,
                &opts.config,
                net_mode,
                opts.monitor,
            );
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

/// Set up parent-side network infrastructure (slirp4netns).
///
/// For filtered mode, we also pre-resolve whitelisted domains to build
/// an IP allow-set. Actual IP-level filtering of connect() syscalls
/// will be enforced via seccomp in Phase 4.
fn setup_parent_network(
    child_pid: Pid,
    config: &SandboxConfig,
    state: &mut NetworkState,
) -> Result<(), can_net::NetError> {
    if !can_net::slirp::is_available() {
        tracing::warn!(
            "slirp4netns not found. Filtered network mode requires slirp4netns. \
             Install it with: sudo apt install slirp4netns"
        );
        return Err(can_net::NetError::Slirp(
            "slirp4netns not found".to_string(),
        ));
    }

    // Pre-resolve whitelisted domains to IPs for future seccomp filtering.
    if !config.network.allow_domains.is_empty() {
        let resolved = can_net::resolve_allowed_domains(&config.network);
        if resolved.is_empty() {
            tracing::warn!("could not resolve any whitelisted domains to IPs");
        } else {
            tracing::info!(
                count = resolved.len(),
                "pre-resolved whitelisted domains to IPs"
            );
            for (domain, ips) in &resolved {
                tracing::debug!(domain, ips = ?ips, "resolved");
            }
        }
        // TODO(Phase 4): Pass resolved IPs to seccomp connect() filter.
    }

    // Start slirp4netns for connectivity.
    let slirp_child = can_net::slirp::start(child_pid)?;
    state.slirp_child = Some(slirp_child);

    Ok(())
}

/// Child process entry point.
///
/// Creates all namespaces atomically in a single `unshare` call, then
/// waits for the parent to write UID/GID maps before proceeding with
/// mount operations that require mapped UIDs.
///
/// Phase 5 additions:
/// - `CLONE_NEWPID` + inner fork so the sandboxed process becomes PID 1
/// - Environment filtering via `env_passthrough`
/// - `RLIMIT_NPROC` for max_pids
/// - `allow_execve` pre-exec validation (done in parent, but path kept for logging)
///
/// Phase 6 additions:
/// - `monitor` flag: when true, enforcement points log violations but don't block.
///   Namespace isolation is still active for accurate observation.
#[allow(clippy::too_many_arguments)]
fn child_entry(
    cmd: &CString,
    argv: &[CString],
    command_path: &Path,
    ready_write: std::os::fd::OwnedFd,
    done_read: std::os::fd::OwnedFd,
    config: &SandboxConfig,
    net_mode: NetworkMode,
    monitor: bool,
) -> Result<(), NamespaceError> {
    // Build clone flags: always user + mount + PID namespaces.
    let mut clone_flags =
        CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID;

    // Add network namespace isolation when not in Full (trust) mode.
    if net_mode != NetworkMode::Full {
        clone_flags |= can_net::netns::NET_NS_FLAG;
        tracing::debug!("including CLONE_NEWNET in unshare");
    }

    // Create namespaces atomically.
    // Doing this in one call avoids issues with AppArmor restrictions
    // that may block sequential namespace creation.
    unshare(clone_flags).map_err(NamespaceError::Unshare)?;

    // Signal parent that namespaces are created.
    let mut ready_w = std::fs::File::from(ready_write);
    ready_w.write_all(&[0u8]).map_err(NamespaceError::UidMap)?;
    drop(ready_w);

    // Wait for parent to write UID/GID maps and set up network.
    let mut buf = [0u8; 1];
    let mut done_r = std::fs::File::from(done_read);
    done_r
        .read_exact(&mut buf)
        .map_err(NamespaceError::UidMap)?;
    drop(done_r);

    tracing::debug!("namespaces created, uid/gid mapped, setting up sandbox");

    if monitor {
        tracing::warn!("MONITOR MODE: namespace isolation active, policy enforcement relaxed");
    }

    // Enter PID namespace via inner fork.
    // CLONE_NEWPID affects children, not the caller. So we fork once more:
    // the child becomes PID 1 in the new PID namespace. The intermediate
    // parent waits and propagates the exit code (never returns here).
    process::enter_pid_namespace()?;

    // From here on, we are PID 1 in the new PID namespace.

    // Detect the package-manager prefix for the command binary.
    // Instead of chasing the full transitive dependency graph, we mount
    // the entire prefix tree (e.g. /nix/store, /opt/homebrew) so all
    // sibling packages are available at runtime. Security is enforced at
    // the exec layer, not the filesystem layer.
    let command_prefix = crate::detect_command_prefix(command_path);
    if let Some(ref prefix) = command_prefix {
        tracing::warn!(
            prefix = %prefix.display(),
            command = %command_path.display(),
            "auto-mounting package prefix for command \
             (add to [filesystem] allow to silence this warning)"
        );
    }

    // Set up isolated filesystem with bind mounts and pivot_root.
    // Falls back to degraded mode if AppArmor blocks mount operations.
    // Must happen AFTER enter_pid_namespace so /proc reflects the new PID ns.
    let fs_isolated = overlay::try_setup_filesystem(&config.filesystem, command_prefix.as_deref())?;
    if fs_isolated {
        tracing::debug!("filesystem isolation active (pivot_root)");
    } else {
        tracing::warn!("filesystem isolation DISABLED — running with host filesystem");
    }

    // Set up network inside the sandbox.
    match net_mode {
        NetworkMode::None => {
            // Bring up loopback so localhost works (e.g., for inter-process comms).
            match can_net::netns::bring_up_loopback() {
                Ok(()) => tracing::debug!("loopback up (network fully isolated)"),
                Err(e) => tracing::warn!(error = %e, "failed to bring up loopback"),
            }
        }
        NetworkMode::Filtered => {
            // In Filtered mode, slirp4netns provides user-mode networking.
            // DNS resolution works via slirp's built-in DNS forwarding.
            // IP-level filtering (connect() interception) will be added
            // in a future phase via seccomp SECCOMP_RET_USER_NOTIF.
            tracing::info!(
                "network: filtered mode via slirp4netns. \
                 NOTE: IP-level connect() filtering not yet enforced"
            );
        }
        NetworkMode::Full => {
            tracing::debug!("network: full access (no isolation)");
        }
    }

    // Apply process resource limits.
    if let Some(max_pids) = config.process.max_pids {
        if monitor {
            tracing::warn!(
                max_pids,
                "MONITOR: would enforce RLIMIT_NPROC={max_pids}, skipping"
            );
        } else {
            process::set_max_pids(max_pids)?;
        }
    }

    // Apply seccomp filter — must be last setup step before exec.
    // In monitor mode, use SECCOMP_RET_LOG so denied syscalls are logged
    // to kernel audit but allowed to proceed. In normal mode, use Errno
    // so the process can handle denials gracefully.
    let profile_name = &config.profile.name;
    let deny_action = if monitor {
        tracing::warn!(
            profile = profile_name,
            "MONITOR: seccomp using LOG action (denied syscalls will be allowed but logged)"
        );
        seccomp::DenyAction::Log
    } else {
        seccomp::DenyAction::Errno
    };
    match seccomp::load_and_apply(profile_name, deny_action) {
        Ok(()) => tracing::debug!(profile = profile_name, "seccomp filter applied"),
        Err(seccomp::SeccompError::EmptyFilter) => {
            tracing::debug!(
                profile = profile_name,
                "no denied syscalls, seccomp skipped"
            );
        }
        Err(e) => {
            tracing::warn!(profile = profile_name, error = %e, "seccomp filter failed");
            return Err(NamespaceError::Seccomp(e));
        }
    }

    // Filter environment variables according to policy.
    // In monitor mode, log what would be stripped but pass full env through.
    let filtered_env = if monitor {
        let would_filter = process::filter_environment(&config.process);
        let full_env = process::full_environment();
        let stripped_count = full_env.len().saturating_sub(would_filter.len());
        if stripped_count > 0 {
            tracing::warn!(
                stripped = stripped_count,
                kept = would_filter.len(),
                total = full_env.len(),
                "MONITOR: would strip {stripped_count} env vars, passing all through"
            );
        }
        full_env
    } else {
        process::filter_environment(&config.process)
    };

    tracing::info!(
        command = %command_path.display(),
        env_vars = filtered_env.len(),
        monitor,
        "executing sandboxed command"
    );

    // Exec the target command with the (possibly filtered) environment.
    nix::unistd::execve(cmd, argv, &filtered_env).map_err(NamespaceError::Exec)?;

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
