use std::ffi::CString;
use std::io::{Read as _, Write as _};
use std::path::Path;

use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork, pipe};

use can_net::{NetworkMode, NetworkState};
use can_policy::SandboxConfig;

use crate::{
    SandboxOpts, cgroups, notifier, overlay, process, resolve_command, seccomp, to_cstring,
};

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

    #[error("cgroup resource limit failed: {0}")]
    Cgroup(#[from] crate::cgroups::CgroupError),

    #[error("seccomp notifier failed: {0}")]
    Notifier(#[from] notifier::NotifierError),
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

    // Determine whether to enable the seccomp notifier.
    let notifier_enabled = resolve_notifier_enabled(&opts.config.syscalls, opts.monitor);

    // Create the fd channel for passing the notifier fd from child to parent.
    // Created before fork so both sides inherit their end.
    let notifier_channel = if notifier_enabled {
        match notifier::create_fd_channel() {
            Ok((parent_fd, child_fd)) => {
                tracing::debug!("created notifier fd channel");
                Some((parent_fd, child_fd))
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to create notifier fd channel, continuing without notifier");
                None
            }
        }
    } else {
        None
    };

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

            // Drop the child end of the notifier channel in the parent.
            let parent_notifier_fd = notifier_channel.map(|(parent_fd, child_fd)| {
                drop(child_fd);
                parent_fd
            });

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
            let mut resolved_ips: Vec<(String, Vec<std::net::IpAddr>)> = Vec::new();
            if net_mode == NetworkMode::Filtered {
                match setup_parent_network(child, &opts.config, &mut net_state, &mut resolved_ips) {
                    Ok(()) => tracing::debug!("parent network setup complete"),
                    Err(e) if opts.strict => {
                        tracing::error!(error = %e, "STRICT: parent network setup failed");
                        return Err(NamespaceError::Network(e));
                    }
                    Err(e) if opts.allow_degraded => {
                        tracing::warn!(error = %e, "parent network setup failed, child will run without filtered network (--allow-degraded)");
                        // Don't fail hard — child will detect missing network
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "parent network setup failed (use --allow-degraded to continue without it)");
                        return Err(NamespaceError::Network(e));
                    }
                }
            }

            // Signal child that maps (and network) are written.
            let mut done_w = std::fs::File::from(parent_done.1);
            done_w.write_all(&[0u8]).map_err(NamespaceError::UidMap)?;
            drop(done_w);

            // Receive the notifier fd from the child and start the supervisor.
            let mut supervisor_handle = None;
            if let Some(parent_fd) = parent_notifier_fd {
                match notifier::recv_fd(&parent_fd) {
                    Ok(notifier_fd) => {
                        let policy = notifier::policy_from_config(&opts.config, &resolved_ips);
                        tracing::info!(
                            allowed_ips = policy.allowed_ips.len(),
                            allowed_cidrs = policy.allowed_cidrs.len(),
                            allowed_exec_paths = policy.allowed_exec_paths.len(),
                            "starting seccomp supervisor"
                        );
                        match notifier::start_supervisor(notifier_fd, policy) {
                            Ok(handle) => {
                                supervisor_handle = Some(handle);
                                tracing::debug!("seccomp supervisor started");
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to start seccomp supervisor");
                            }
                        }

                        #[cfg(test)]
                        mod tests {
                            use super::*;
                            use can_policy::SyscallConfig;

                            #[test]
                            fn resolve_notifier_disabled_in_monitor_mode() {
                                let config = SyscallConfig::default();
                                assert!(!resolve_notifier_enabled(&config, true));
                            }

                            #[test]
                            fn resolve_notifier_explicit_true() {
                                let mut config = SyscallConfig::default();
                                config.notifier = Some(true);
                                assert!(resolve_notifier_enabled(&config, false));
                            }

                            #[test]
                            fn resolve_notifier_explicit_false() {
                                let mut config = SyscallConfig::default();
                                config.notifier = Some(false);
                                assert!(!resolve_notifier_enabled(&config, false));
                            }

                            #[test]
                            fn resolve_notifier_explicit_true_still_disabled_in_monitor() {
                                let mut config = SyscallConfig::default();
                                config.notifier = Some(true);
                                // Monitor mode takes priority over explicit config.
                                assert!(!resolve_notifier_enabled(&config, true));
                            }

                            #[test]
                            fn resolve_notifier_auto_detect_returns_bool() {
                                // Auto-detect: None means check kernel version.
                                // We can't predict the result, but it shouldn't panic.
                                let config = SyscallConfig::default();
                                let _ = resolve_notifier_enabled(&config, false);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to receive notifier fd from child");
                    }
                }
            }

            let result = wait_for_child(child);

            // Clean up: supervisor first (closes ioctl fd), then network.
            if let Some(handle) = supervisor_handle {
                handle.shutdown();
            }
            net_state.shutdown();

            result
        }
        ForkResult::Child => {
            drop(child_ready.0);
            drop(parent_done.1);

            // Drop the parent end of the notifier channel in the child.
            let child_notifier_fd = notifier_channel.map(|(parent_fd, child_fd)| {
                drop(parent_fd);
                child_fd
            });

            let result = child_entry(
                &cmd,
                &argv,
                &command_path,
                child_ready.1,
                parent_done.0,
                &opts.config,
                net_mode,
                opts.monitor,
                opts.strict,
                opts.allow_degraded,
                child_notifier_fd,
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

/// Set up parent-side network infrastructure (slirp4netns + DNS proxy).
///
/// For filtered mode, we pre-resolve whitelisted domains to build an IP
/// allow-set for the seccomp notifier's connect() filtering. We also
/// start the DNS proxy and wire slirp4netns to use it.
fn setup_parent_network(
    child_pid: Pid,
    config: &SandboxConfig,
    state: &mut NetworkState,
    resolved_ips: &mut Vec<(String, Vec<std::net::IpAddr>)>,
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

    // Pre-resolve whitelisted domains to IPs for seccomp connect() filtering.
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
        *resolved_ips = resolved;
    }

    // Start the DNS proxy if there are domain-based rules.
    // The DNS proxy filters queries: whitelisted domains are forwarded,
    // others get REFUSED.
    let has_domain_rules = !config.network.allow_domains.is_empty();
    if has_domain_rules {
        let dns_config = can_net::dns::DnsProxyConfig::default_with_policy(config.network.clone());
        match can_net::dns::start_dns_proxy(dns_config) {
            Ok(handle) => {
                let dns_port = handle.local_port();
                tracing::info!(port = dns_port, "DNS proxy started");
                state.dns_shutdown = Some(handle);

                // Start slirp4netns with DNS forwarded to our proxy.
                let slirp_child = can_net::slirp::start_with_dns(child_pid, dns_port)?;
                state.slirp_child = Some(slirp_child);
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(error = %e, "DNS proxy failed to start, falling back to plain slirp");
            }
        }
    }

    // Start slirp4netns without custom DNS (no domain rules, or DNS proxy failed).
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
///
/// Security hardening:
/// - `strict` flag: when true, any setup failure is fatal and seccomp uses
///   KILL_PROCESS instead of ERRNO. Intended for CI / production.
/// - `allow_degraded` flag: when true, sandbox may continue with reduced
///   isolation if setup fails. When false (default), setup failures are fatal.
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
    strict: bool,
    allow_degraded: bool,
    notifier_channel: Option<std::os::fd::OwnedFd>,
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

    // Set up isolated filesystem with bind mounts and pivot_root.
    // All necessary paths (essential OS mounts, auto-detected package manager
    // prefixes, and user-specified paths) are pre-merged into config.filesystem
    // via recipe composition in the CLI layer.
    // By default, failures are fatal. Only with --allow-degraded does the sandbox
    // fall back to degraded mode (host filesystem) if AppArmor blocks mount ops.
    // Must happen AFTER enter_pid_namespace so /proc reflects the new PID ns.
    let fs_isolated = overlay::try_setup_filesystem(&config.filesystem)?;
    if fs_isolated {
        tracing::debug!("filesystem isolation active (pivot_root)");
    } else if allow_degraded {
        tracing::warn!(
            "filesystem isolation DISABLED — running with host filesystem (--allow-degraded)"
        );
    } else if strict {
        tracing::error!("STRICT: filesystem isolation failed — aborting");
        return Err(NamespaceError::Overlay(overlay::OverlayError::Mount {
            path: "/ (strict mode requires full isolation)".to_string(),
            source: nix::Error::EPERM,
        }));
    } else {
        tracing::error!(
            "filesystem isolation failed — aborting (use --allow-degraded to permit degraded mode)"
        );
        return Err(NamespaceError::Overlay(overlay::OverlayError::Mount {
            path: "/ (filesystem isolation required; use --allow-degraded to run without it)"
                .to_string(),
            source: nix::Error::EPERM,
        }));
    }

    // Set up network inside the sandbox.
    match net_mode {
        NetworkMode::None => {
            // Bring up loopback so localhost works (e.g., for inter-process comms).
            match can_net::netns::bring_up_loopback() {
                Ok(()) => tracing::debug!("loopback up (network fully isolated)"),
                Err(e) if strict => {
                    tracing::error!(error = %e, "STRICT: failed to bring up loopback");
                    return Err(NamespaceError::Network(e));
                }
                Err(e) if allow_degraded => {
                    tracing::warn!(error = %e, "failed to bring up loopback (--allow-degraded)");
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to bring up loopback (use --allow-degraded to continue)");
                    return Err(NamespaceError::Network(e));
                }
            }
        }
        NetworkMode::Filtered => {
            // In Filtered mode, slirp4netns provides user-mode networking.
            // The parent-side DNS proxy filters queries by domain allowlist.
            // The seccomp USER_NOTIF supervisor filters connect() by IP.
            // Override resolv.conf to point at the DNS proxy (127.0.0.1).
            if let Err(e) = can_net::netns::write_resolv_conf("10.0.2.3") {
                tracing::warn!(error = %e, "failed to write sandbox resolv.conf, DNS may not work");
            }
            tracing::info!(
                notifier = notifier_channel.is_some(),
                "network: filtered mode via slirp4netns + seccomp notifier"
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

    // Apply cgroup v2 resource limits (memory, CPU).
    let has_cgroup_limits =
        config.resources.memory_mb.is_some() || config.resources.cpu_percent.is_some();
    if has_cgroup_limits {
        if monitor {
            tracing::warn!(
                memory_mb = ?config.resources.memory_mb,
                cpu_percent = ?config.resources.cpu_percent,
                "MONITOR: would enforce cgroup resource limits, skipping"
            );
        } else {
            match cgroups::apply_limits(config.resources.memory_mb, config.resources.cpu_percent) {
                Ok(Some(path)) => {
                    tracing::info!(path = %path.display(), "cgroup resource limits applied");
                }
                Ok(None) => {} // no limits configured
                Err(e) if strict => {
                    tracing::error!(error = %e, "STRICT: cgroup resource limits failed");
                    return Err(NamespaceError::Cgroup(e));
                }
                Err(e) if allow_degraded => {
                    tracing::warn!(
                        error = %e,
                        "cgroup resource limits unavailable — running without memory/CPU limits (--allow-degraded)"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "cgroup resource limits failed (use --allow-degraded to continue without them)"
                    );
                    return Err(NamespaceError::Cgroup(e));
                }
            }
        }
    }

    // Install the seccomp notifier filter BEFORE the main filter.
    //
    // The kernel evaluates seccomp filters in reverse install order, so the
    // last-installed filter runs first. By installing the notifier filter
    // first and the main filter second, the main filter runs first for most
    // syscalls. BUT: for syscalls that match USER_NOTIF, the notifier filter
    // (installed first, evaluated second) would normally be shadowed. That's
    // actually wrong — we need the notifier filter to run first.
    //
    // Correction: we install the notifier filter SECOND (after the main filter),
    // so it runs FIRST in the kernel's reverse-order evaluation. But we need
    // the notifier fd before the main filter is installed. So the actual order
    // must be:
    //   1. Install notifier filter (returns fd) — this runs first in kernel
    //   2. Send fd to parent
    //   3. Install main filter — this runs second in kernel
    //
    // This is correct: the notifier filter catches connect/clone/socket/execve
    // with USER_NOTIF (supervisor decides), and the main filter handles
    // everything else. The kernel takes the most restrictive result when
    // multiple filters match, but USER_NOTIF is special — it suspends the
    // syscall for supervisor decision, which takes precedence.
    if let Some(channel_fd) = notifier_channel {
        match notifier::install_notifier_filter() {
            Ok(notifier_fd) => {
                tracing::debug!("installed USER_NOTIF seccomp filter in child");
                if let Err(e) = notifier::send_fd(&channel_fd, &notifier_fd) {
                    tracing::warn!(error = %e, "failed to send notifier fd to parent");
                }
                // Close both fds — the parent now has the notifier fd.
                drop(notifier_fd);
                drop(channel_fd);
            }
            Err(e) if allow_degraded => {
                tracing::warn!(error = %e, "notifier filter install failed (--allow-degraded), continuing without it");
                drop(channel_fd);
            }
            Err(e) if strict => {
                tracing::error!(error = %e, "STRICT: notifier filter install failed");
                return Err(NamespaceError::Notifier(e));
            }
            Err(e) => {
                tracing::error!(error = %e, "notifier filter install failed (use --allow-degraded to skip)");
                return Err(NamespaceError::Notifier(e));
            }
        }
    }

    // Apply seccomp filter — must be last setup step before exec.
    // In monitor mode, use SECCOMP_RET_LOG so denied syscalls are logged
    // to kernel audit but allowed to proceed. In strict mode, use
    // KILL_PROCESS so violations terminate immediately. In normal mode,
    // use Errno so the process can handle denials gracefully.
    let seccomp_mode = config.syscalls.seccomp_mode();
    let deny_action = if monitor {
        tracing::warn!(
            %seccomp_mode,
            "MONITOR: seccomp using LOG action (denied syscalls will be allowed but logged)"
        );
        seccomp::DenyAction::Log
    } else if strict {
        tracing::info!(
            %seccomp_mode,
            "STRICT: seccomp using KILL_PROCESS action"
        );
        seccomp::DenyAction::KillProcess
    } else {
        seccomp::DenyAction::Errno
    };
    match seccomp::load_and_apply(&config.syscalls, deny_action) {
        Ok(()) => tracing::debug!("seccomp filter applied"),
        Err(seccomp::SeccompError::EmptyFilter) => {
            tracing::debug!("no denied syscalls, seccomp skipped");
        }
        Err(e) if strict => {
            tracing::error!(error = %e, "STRICT: seccomp filter failed");
            return Err(NamespaceError::Seccomp(e));
        }
        Err(e) => {
            tracing::warn!(error = %e, "seccomp filter failed");
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

/// Determine whether the seccomp USER_NOTIF supervisor should be enabled.
///
/// Resolution logic:
/// 1. If the config explicitly sets `notifier = false`, disable.
/// 2. If the config explicitly sets `notifier = true`, enable.
/// 3. If `None` (auto-detect): enable if the kernel supports it (Linux 5.9+).
/// 4. In monitor mode, the notifier is always disabled (it would interfere
///    with the LOG-only seccomp policy).
fn resolve_notifier_enabled(syscall_config: &can_policy::SyscallConfig, monitor: bool) -> bool {
    if monitor {
        tracing::debug!("notifier disabled: monitor mode");
        return false;
    }

    match syscall_config.notifier_enabled() {
        Some(true) => {
            tracing::debug!("notifier enabled: explicit config");
            true
        }
        Some(false) => {
            tracing::debug!("notifier disabled: explicit config");
            false
        }
        None => {
            let supported = notifier::is_notifier_supported();
            tracing::debug!(supported, "notifier auto-detect (requires Linux 5.9+)");
            supported
        }
    }
}
