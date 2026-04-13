use std::ffi::CString;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

use nix::sched::{CloneFlags, unshare};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork, pipe};

/// PID of the child process, used by signal handlers to forward signals.
/// Set to -1 when no child exists.
static CHILD_PID: AtomicI32 = AtomicI32::new(-1);

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
/// The protocol between parent, child, and grandchild:
///
/// 1. Parent validates command against `allow_execve` whitelist
/// 2. Parent pre-resolves DNS for whitelisted domains (if filtered network)
/// 3. Parent forks → child
/// 4. Child calls `unshare(CLONE_NEWUSER | CLONE_NEWPID [| CLONE_NEWNET])` atomically
/// 5. Child signals parent via pipe that namespaces are created
/// 6. Parent writes UID/GID maps, signals child
/// 7. Parent starts pasta (with `--userns` + `--netns` pointing at
///    `/proc/<child_pid>/ns/*`) and the DNS proxy
/// 8. Parent signals child that network is ready
/// 9. Child creates mount namespace (CLONE_NEWNS) — this is deferred so
///    the parent can still access `/proc/<child_pid>/ns/*` via the init
///    mount namespace's procfs
/// 10. Child forks again for PID namespace:
///    - **Intermediate process**: receives seccomp notifier fd from inner child,
///      runs the supervisor thread (inside the user namespace so `/proc/<pid>/mem`
///      access works), waits for inner child, shuts down supervisor, exits.
///    - **Inner child (PID 1)**: sets up filesystem, network, RLIMIT_NPROC,
///      seccomp, env filtering, installs notifier filter, sends fd to
///      intermediate, then execs the target command.
/// 11. Parent waits for child and cleans up network.
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

    // Pre-resolve whitelisted domains to IPs BEFORE forking.
    // Both parent and child need the resolved IPs: the parent for reference,
    // the child to build the NotifierPolicy for the supervisor.
    // Done here (before fork) so the child inherits the results.
    let resolved_ips =
        if net_mode == NetworkMode::Filtered && !opts.config.network.allow_domains.is_empty() {
            let resolved = can_net::resolve_allowed_domains(&opts.config.network);
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
            resolved
        } else {
            Vec::new()
        };

    // Create pipes for parent-child synchronization.
    //
    // The protocol has two phases:
    // Phase 1: child unshares → child_ready → parent writes uid_map → maps_done
    // Phase 2: parent starts pasta (using /proc/<child_pid>/ns/*) → network_done → child continues
    //
    // No bind-mount is needed: pasta is invoked with --userns and --netns
    // pointing directly at /proc/<child_pid>/ns/{user,net}. These files
    // are world-readable symlinks, so pasta can open them directly.
    let child_ready = pipe().map_err(NamespaceError::Fork)?;
    let maps_done = pipe().map_err(NamespaceError::Fork)?;
    let network_done = pipe().map_err(NamespaceError::Fork)?;

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
            drop(maps_done.0);
            drop(network_done.0);

            // Phase 1: Wait for child to signal that namespaces are created.
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

            // Signal child that uid/gid maps are written.
            let mut maps_w = std::fs::File::from(maps_done.1);
            maps_w.write_all(&[0u8]).map_err(NamespaceError::UidMap)?;
            drop(maps_w);

            // Phase 2: Start pasta with --userns + --netns /proc/<child_pid>/ns/*.
            //
            // The child called prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) before
            // signaling us, allowing pasta (a sibling process) to open
            // /proc/<child_pid>/ns/* despite Yama ptrace_scope=1.
            //
            // pasta must join the user namespace first (setns(CLONE_NEWUSER))
            // to acquire CAP_SYS_ADMIN over the network namespace, then join
            // the network namespace (setns(CLONE_NEWNET)).
            let mut net_state = NetworkState::new();
            if net_mode == NetworkMode::Filtered {
                match setup_parent_network(child.as_raw() as u32, &opts.config, &mut net_state) {
                    Ok(()) => tracing::debug!("parent network setup complete"),
                    Err(e) => {
                        tracing::error!(error = %e, "parent network setup failed");
                        return Err(NamespaceError::Network(e));
                    }
                }
            }

            // Signal child that network is ready.
            let mut net_w = std::fs::File::from(network_done.1);
            net_w.write_all(&[0u8]).map_err(NamespaceError::UidMap)?;
            drop(net_w);

            // Forward SIGTERM/SIGINT to the child process so that killing
            // `can run` propagates into the sandbox. The signal handler uses
            // the CHILD_PID atomic to find the target.
            CHILD_PID.store(child.as_raw(), Ordering::Release);
            install_signal_forwarder();

            let result = wait_for_child(child);

            CHILD_PID.store(-1, Ordering::Release);
            net_state.shutdown();

            result
        }
        ForkResult::Child => {
            drop(child_ready.0);
            drop(maps_done.1);
            drop(network_done.1);

            // If the parent (original `can run`) dies, kill this child.
            // This prevents orphaned namespace processes when the user
            // kills the `can run` process or it crashes.
            set_pdeathsig(libc::SIGKILL);

            let result = child_entry(
                &cmd,
                &argv,
                &command_path,
                child_ready.1,
                maps_done.0,
                network_done.0,
                &opts.config,
                net_mode,
                opts.monitor,
                opts.strict,
                notifier_enabled,
                &resolved_ips,
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

/// Set up parent-side network infrastructure (pasta).
///
/// `child_pid` is the PID of the sandboxed child process. pasta is
/// invoked with `--userns /proc/<pid>/ns/user` and `--netns /proc/<pid>/ns/net`.
/// DNS resolution is handled by the seccomp notifier's domain-aware
/// filtering — no separate DNS proxy is needed.
fn setup_parent_network(
    child_pid: u32,
    config: &SandboxConfig,
    state: &mut NetworkState,
) -> Result<(), can_net::NetError> {
    if !can_net::pasta::is_available() {
        tracing::warn!(
            "pasta not found. Filtered network mode requires pasta. \
             Install it with: sudo apt install passt"
        );
        return Err(can_net::NetError::Pasta("pasta not found".to_string()));
    }

    let pasta_config = can_net::pasta::PastaConfig {
        ports: config.network.ports.clone(),
        child_pid: Some(child_pid),
    };

    // Start pasta to provide networking in the sandbox.
    let pasta_child = can_net::pasta::start(&pasta_config)?;
    state.pasta_child = Some(pasta_child);

    Ok(())
}

/// Child process entry point.
///
/// Creates user + PID [+ net] namespaces, then coordinates with the
/// parent via pipes:
/// 1. Signal parent that namespaces are created (child_ready)
/// 2. Wait for parent to write UID/GID maps (maps_done)
/// 3. Wait for parent to start pasta (network_done)
/// 4. Create mount namespace and continue sandbox setup
///
/// The seccomp USER_NOTIF supervisor runs in the intermediate process
/// (after `enter_pid_namespace`'s inner fork) rather than in the original
/// parent. This is required because `/proc/<pid>/mem` reads fail across
/// user namespace boundaries for unprivileged processes. By running the
/// supervisor inside the same user namespace as the sandboxed process,
/// it has the necessary access to read child process memory.
#[allow(clippy::too_many_arguments)]
fn child_entry(
    cmd: &CString,
    argv: &[CString],
    command_path: &Path,
    ready_write: OwnedFd,
    maps_read: OwnedFd,
    network_read: OwnedFd,
    config: &SandboxConfig,
    net_mode: NetworkMode,
    monitor: bool,
    strict: bool,
    notifier_enabled: bool,
    resolved_ips: &[(String, Vec<std::net::IpAddr>)],
) -> Result<(), NamespaceError> {
    // Build clone flags for the first unshare: user + PID [+ net] namespaces.
    //
    // CLONE_NEWNS (mount namespace) is deliberately excluded here and done
    // in a second unshare() call AFTER the parent has started pasta. If we
    // included CLONE_NEWNS here, the parent couldn't access our
    // /proc/<pid>/ns/* files because the child's /proc would be in an
    // isolated mount namespace.
    let mut clone_flags = CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID;

    // Add network namespace isolation when not in Full (trust) mode.
    if net_mode != NetworkMode::Full {
        clone_flags |= can_net::netns::NET_NS_FLAG;
        tracing::debug!("including CLONE_NEWNET in unshare");
    }

    // Create user + PID [+ net] namespaces.
    unshare(clone_flags).map_err(NamespaceError::Unshare)?;

    // Allow pasta (a sibling process) to access our /proc/<pid>/ns/* files.
    //
    // Yama ptrace_scope=1 restricts /proc/<pid>/ns/* access to ancestor
    // processes or those with CAP_SYS_PTRACE. Since pasta is spawned by
    // the parent (our sibling, not ancestor), it would fail to open
    // /proc/<our_pid>/ns/net without this.
    //
    // PR_SET_PTRACER with PR_SET_PTRACER_ANY tells Yama to allow any
    // process to access our /proc/<pid>/ns/* files. This is safe because:
    // - The sandbox process is already isolated in its own user namespace
    // - PR_SET_PTRACER only relaxes the Yama ancestry check, not other
    //   permission checks (user namespace membership, etc.)
    // - The setting is per-process and dies with the process
    //
    // We call this BEFORE signaling the parent so pasta can immediately
    // access /proc/<child>/ns/net when the parent starts it.
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0);
    }

    // Signal parent that namespaces are created.
    let mut ready_w = std::fs::File::from(ready_write);
    ready_w.write_all(&[0u8]).map_err(NamespaceError::UidMap)?;
    drop(ready_w);

    // Wait for parent to write UID/GID maps.
    let mut buf = [0u8; 1];
    let mut maps_r = std::fs::File::from(maps_read);
    maps_r
        .read_exact(&mut buf)
        .map_err(NamespaceError::UidMap)?;
    drop(maps_r);

    tracing::debug!("uid/gid maps written, proceeding with namespace setup");

    // Wait for parent to start pasta and complete network setup.
    // The parent spawns pasta with --userns + --netns pointing at our
    // /proc/<pid>/ns/* paths. Pasta joins our user namespace first (to
    // acquire CAP_SYS_ADMIN), then our network namespace.
    let mut net_r = std::fs::File::from(network_read);
    net_r.read_exact(&mut buf).map_err(NamespaceError::UidMap)?;
    drop(net_r);

    tracing::debug!("network ready, continuing sandbox setup");

    // Now create the mount namespace. This is done as a second unshare() call
    // after pasta has started so that /proc/<child_pid>/ns/* paths remain
    // accessible to pasta via the init mount namespace's procfs. After this
    // call, our mount namespace is isolated and we can proceed with pivot_root.
    unshare(CloneFlags::CLONE_NEWNS).map_err(NamespaceError::Unshare)?;
    tracing::debug!("mount namespace created");

    if monitor {
        tracing::warn!("MONITOR MODE: namespace isolation active, policy enforcement relaxed");
    }

    // Build the notifier policy and create the fd channel for passing the
    // notifier fd from the worker child to the PID-1 supervisor.
    // The supervisor runs as PID 1 inside the same user + PID namespace
    // as the sandboxed processes, so /proc/<pid>/mem access works.
    let supervisor_context = if notifier_enabled {
        let policy = notifier::policy_from_config(config, resolved_ips);
        let dynamic_allowlist = notifier::DynamicAllowlist::new();
        tracing::info!(
            allowed_ips = policy.allowed_ips.len(),
            allowed_cidrs = policy.allowed_cidrs.len(),
            allowed_domains = policy.allowed_domains.len(),
            allowed_exec_paths = policy.allowed_exec_paths.len(),
            allowed_exec_prefixes = policy.allowed_exec_prefixes.len(),
            "notifier policy built for supervisor"
        );
        match notifier::create_fd_channel() {
            Ok((recv_fd, send_fd)) => {
                tracing::debug!("created notifier fd channel (worker → PID-1 supervisor)");
                Some((policy, dynamic_allowlist, recv_fd, send_fd))
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to create notifier fd channel");
                return Err(NamespaceError::Notifier(e));
            }
        }
    } else {
        None
    };

    // Enter PID namespace via fork(s).
    //
    // CLONE_NEWPID affects children, not the caller. So we fork:
    // the child becomes PID 1 in the new PID namespace.
    //
    // When the notifier is enabled, a second fork occurs inside the new
    // PID namespace: PID 1 becomes the seccomp supervisor, and the worker
    // child (PID 2+) returns here to continue sandbox setup.
    //
    // The supervisor as PID 1:
    //   1. Mounts /proc owned by the user namespace (for /proc/<pid>/mem)
    //   2. Receives the notifier fd from the worker via SCM_RIGHTS
    //   3. Runs the supervisor loop inline (single-threaded)
    //   4. Monitors the worker via non-blocking waitpid
    //   5. Exits when the worker exits (killing all PID ns processes)
    //
    // The supervisor runs inside the same user + PID namespace as the
    // sandboxed processes, so /proc/<pid>/mem access works without
    // cross-namespace permission issues.
    enter_pid_namespace_supervised(supervisor_context)?;

    // --- From here on, we are the worker process in the new PID namespace. ---
    // When the notifier is enabled, we are PID 2+ (PID 1 is the supervisor).
    // When disabled, we are PID 1. The intermediate process and PID-1
    // supervisor never reach this point (they exit in enter_pid_namespace_supervised).

    // Capture the host CWD before pivot_root changes the root filesystem.
    // After pivot_root the original CWD path becomes inaccessible.
    let host_cwd = std::env::current_dir().ok();
    if let Some(ref cwd) = host_cwd {
        tracing::debug!(cwd = %cwd.display(), "captured host CWD for sandbox mount");
    }

    // Apply cgroup v2 resource limits (memory, CPU).
    // Must happen BEFORE pivot_root — after pivot_root, /sys/fs/cgroup is
    // no longer the host's cgroupfs and cgroup.controllers won't be found.
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
                Err(e) => {
                    tracing::error!(error = %e, "cgroup resource limits failed");
                    return Err(NamespaceError::Cgroup(e));
                }
            }
        }
    }

    // Set up isolated filesystem with bind mounts and pivot_root.
    // All necessary paths (essential OS mounts, auto-detected package manager
    // prefixes, and user-specified paths) are pre-merged into config.filesystem
    // via recipe composition in the CLI layer.
    // Failures are always fatal — the sandbox aborts if filesystem isolation
    // cannot be established (e.g., AppArmor blocks mount operations).
    // Must happen AFTER enter_pid_namespace so /proc reflects the new PID ns.
    let fs_isolated = overlay::try_setup_filesystem(&config.filesystem, host_cwd.as_deref())?;
    if fs_isolated {
        tracing::debug!("filesystem isolation active (pivot_root)");
    } else {
        tracing::error!("filesystem isolation failed — aborting");
        return Err(NamespaceError::Overlay(overlay::OverlayError::Mount {
            path: "/ (filesystem isolation required)".to_string(),
            source: nix::Error::EPERM,
        }));
    }

    // Set up network inside the sandbox.
    match net_mode {
        NetworkMode::None => {
            // Bring up loopback so localhost works (e.g., for inter-process comms).
            match can_net::netns::bring_up_loopback() {
                Ok(()) => tracing::debug!("loopback up (network fully isolated)"),
                Err(e) => {
                    tracing::error!(error = %e, "failed to bring up loopback");
                    return Err(NamespaceError::Network(e));
                }
            }
        }
        NetworkMode::Filtered => {
            // In Filtered mode, pasta provides user-mode networking.
            // The parent-side DNS proxy filters queries by domain allowlist.
            // The seccomp USER_NOTIF supervisor filters connect() by IP.
            // pasta configures resolv.conf via --dns, but if that doesn't
            // take effect (e.g., after pivot_root), write it explicitly.
            if let Err(e) = can_net::netns::write_resolv_conf(can_net::pasta::PASTA_DNS_ADDR) {
                tracing::warn!(error = %e, "failed to write sandbox resolv.conf, DNS may not work");
            }
            tracing::info!(
                notifier = notifier_enabled,
                "network: filtered mode via pasta + seccomp notifier"
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

    // Install the seccomp notifier filter BEFORE the main filter.
    //
    // The kernel evaluates seccomp filters in reverse install order, so the
    // last-installed filter runs first. We install the notifier filter first
    // (evaluated second by kernel) and the main filter second (evaluated first).
    // For USER_NOTIF syscalls, the notifier filter suspends the syscall for
    // supervisor decision. The main filter handles everything else.
    //
    // The notifier fd is sent to the PID-1 supervisor (running in the
    // same user + PID namespace) via the fd channel created before
    // enter_pid_namespace.
    if notifier_enabled {
        // Retrieve the send end of the fd channel that was stashed by
        // enter_pid_namespace_supervised in the worker child.
        let send_fd = NOTIFIER_SEND_FD
            .lock()
            .unwrap()
            .take()
            .expect("NOTIFIER_SEND_FD must be set when notifier is enabled");

        match notifier::install_notifier_filter() {
            Ok(notifier_fd) => {
                tracing::debug!("installed USER_NOTIF seccomp filter in worker");
                if let Err(e) = notifier::send_fd(&send_fd, &notifier_fd) {
                    tracing::error!(error = %e, "failed to send notifier fd to supervisor");
                    return Err(NamespaceError::Notifier(e));
                }
                // Close the pipe write end — we're done sending.
                drop(send_fd);
                // Keep notifier_fd alive until exec(). The supervisor uses
                // pidfd_getfd() to duplicate it from our fd table, so it
                // must remain open. The kernel sets O_CLOEXEC on seccomp
                // listener fds, so exec() will close it automatically.
                std::mem::forget(notifier_fd);
            }
            Err(e) => {
                tracing::error!(error = %e, "notifier filter install failed");
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

    // Set SELinux exec context so the child transitions to canister_sandboxed_t.
    // This is a no-op on non-SELinux systems and on AppArmor (which uses profile
    // rules for domain transitions). Must be called after seccomp setup but
    // before execve.
    crate::mac::set_child_selinux_context().ok();

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
        match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => return Ok(code),
            Ok(WaitStatus::Signaled(_, signal, _)) => {
                tracing::warn!(%signal, "sandboxed process killed by signal");
                return Ok(128 + signal as i32);
            }
            Err(nix::Error::EINTR) => continue,
            Err(e) => return Err(NamespaceError::Wait(e)),
            Ok(_) => continue,
        }
    }
}

/// Set `PR_SET_PDEATHSIG` so this process receives `sig` when its parent dies.
///
/// This is critical for process cleanup: without it, forked sandbox
/// processes become orphans when the user kills the `can run` process.
fn set_pdeathsig(sig: libc::c_int) {
    // SAFETY: prctl with PR_SET_PDEATHSIG is safe and has no pointer args.
    let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, sig) };
    if ret != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "failed to set PR_SET_PDEATHSIG"
        );
    }
}

/// Install a signal handler that forwards SIGTERM and SIGINT to the child
/// process stored in [`CHILD_PID`].
///
/// The handler is async-signal-safe: it only uses `kill()` and atomic loads.
fn install_signal_forwarder() {
    // SAFETY: The signal handler only calls async-signal-safe functions
    // (kill) and reads an atomic variable.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            forward_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            forward_signal as *const () as libc::sighandler_t,
        );
    }
}

/// Async-signal-safe signal handler that forwards the signal to the child.
extern "C" fn forward_signal(sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::Acquire);
    if pid > 0 {
        // SAFETY: kill is async-signal-safe.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// Enter a new PID namespace, optionally with a seccomp supervisor.
///
/// Forks once: the inner child becomes PID 1 in the new PID namespace and
/// returns `Ok(())` to the caller. The intermediate (parent of the fork)
/// never returns — it runs the supervisor (if enabled), waits for the inner
/// child, and exits with the child's exit code.
///
/// # Supervisor architecture
///
/// When `supervisor_context` is `Some((policy, dynamic_allowlist, recv_fd, send_fd))`:
/// - The intermediate process closes `send_fd`, receives the notifier fd
///   from the inner child via `recv_fd`, starts the supervisor thread,
///   waits for the inner child, then shuts down the supervisor.
/// - The inner child keeps `send_fd` (for later use to send the notifier
///   fd after installing the seccomp filter) and closes `recv_fd`.
///
/// The supervisor runs inside the same user namespace as the sandboxed
/// process, which is critical: unprivileged processes cannot open
/// `/proc/<pid>/mem` across user namespace boundaries. By running the
/// Enter a new PID namespace with optional seccomp supervisor.
///
/// This function forks to create a new PID namespace. The behavior depends
/// on whether the supervisor is enabled:
///
/// ## Without supervisor (supervisor_context is None):
///
/// A single fork creates PID 1 in the new PID namespace. This process
/// returns to the caller to continue sandbox setup.
///
/// ```text
/// intermediate (parent, old PID ns) → waitpid → exit
/// inner child (PID 1, new PID ns) → returns to caller
/// ```
///
/// ## With supervisor (supervisor_context is Some):
///
/// Two forks create the supervisor as PID 1 and the worker as PID 2+:
///
/// ```text
/// intermediate (parent, old PID ns) → waitpid → exit
/// PID 1 (new PID ns, supervisor):
///   - mounts /proc owned by the user namespace
///   - receives notifier fd from worker
///   - runs supervisor loop + monitors worker
///   - exits when worker exits
/// worker (PID 2+, new PID ns):
///   - returns to caller for sandbox setup
///   - installs seccomp filter, sends notifier fd to PID 1
///   - exec's the sandboxed command
/// ```
///
/// PID 1 is the natural supervisor because:
/// - It's in the same PID namespace AND user namespace as all sandboxed
///   processes, so it can mount procfs and read /proc/<pid>/mem
/// - It's an ancestor of all processes in the PID namespace, satisfying
///   Yama ptrace_scope=1
/// - When it exits, the kernel kills all remaining processes in the
///   PID namespace
fn enter_pid_namespace_supervised(
    supervisor_context: Option<(
        notifier::NotifierPolicy,
        notifier::DynamicAllowlist,
        OwnedFd,
        OwnedFd,
    )>,
) -> Result<(), NamespaceError> {
    // SAFETY: fork is safe here because we're in the child process after the
    // initial fork, before spawning any threads.
    match unsafe { nix::unistd::fork() }.map_err(process::ProcessError::PidFork)? {
        nix::unistd::ForkResult::Parent { child } => {
            // Intermediate process (old PID namespace): wait for PID 1 child.
            // Drop all supervisor-related fds.
            drop(supervisor_context);

            // Forward signals to PID 1 child so that killing the parent
            // chain propagates cleanly into the PID namespace.
            CHILD_PID.store(child.as_raw(), Ordering::Release);
            install_signal_forwarder();

            // Wait for PID 1 in a loop that handles EINTR (from signal
            // forwarding) and retries.
            let code = loop {
                match nix::sys::wait::waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => break code,
                    Ok(WaitStatus::Signaled(_, signal, _)) => break 128 + signal as i32,
                    Err(nix::Error::EINTR) => continue,
                    Err(_) | Ok(_) => break 1,
                }
            };
            std::process::exit(code);
        }
        nix::unistd::ForkResult::Child => {
            // We are now PID 1 in the new PID namespace.
            // If the intermediate parent dies, kill us — this tears down
            // the entire PID namespace (kernel kills all processes when
            // PID 1 exits).
            set_pdeathsig(libc::SIGKILL);
            nix::unistd::setsid().map_err(process::ProcessError::PidFork)?;

            match supervisor_context {
                None => {
                    // No supervisor — this process continues as the sandbox worker.
                    tracing::debug!(
                        pid = std::process::id(),
                        "entered PID namespace as PID 1 (no supervisor)"
                    );
                    Ok(())
                }
                Some((policy, dynamic_allowlist, recv_fd, send_fd)) => {
                    // PID 1 becomes the supervisor. Fork a worker child.
                    //
                    // SAFETY: still single-threaded in the forked child.
                    match unsafe { nix::unistd::fork() }.map_err(process::ProcessError::PidFork)? {
                        nix::unistd::ForkResult::Parent { child: worker } => {
                            // PID 1: supervisor process.
                            drop(send_fd); // Only worker sends.

                            // Mount /proc for our PID namespace.
                            // This procfs is owned by our user namespace, so
                            // /proc/<pid>/mem access works without cross-ns issues.
                            // The PIDs visible here match the seccomp notification's
                            // pid field (both use this PID namespace).
                            mount_supervisor_proc();

                            // Receive the notifier fd from the worker.
                            match notifier::recv_fd(&recv_fd, worker.as_raw()) {
                                Ok(notifier_fd) => {
                                    drop(recv_fd);
                                    tracing::info!(
                                        worker_pid = worker.as_raw(),
                                        "seccomp supervisor running as PID 1"
                                    );
                                    let code = notifier::run_supervisor_with_child(
                                        notifier_fd,
                                        &policy,
                                        &dynamic_allowlist,
                                        worker,
                                    );
                                    std::process::exit(code);
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "failed to receive notifier fd from worker"
                                    );
                                    let _ =
                                        nix::sys::signal::kill(worker, nix::sys::signal::SIGKILL);
                                    let _ = waitpid(worker, None);
                                    std::process::exit(126);
                                }
                            }
                        }
                        nix::unistd::ForkResult::Child => {
                            // Worker child: close recv end (supervisor receives).
                            drop(recv_fd);

                            // Stash the send fd for later — child_entry will
                            // retrieve it after installing the seccomp filter.
                            *NOTIFIER_SEND_FD.lock().unwrap() = Some(send_fd);

                            tracing::debug!(
                                pid = std::process::id(),
                                "entered PID namespace as worker"
                            );
                            Ok(())
                        }
                    }
                }
            }
        }
    }
}

/// Mount /proc in the supervisor's mount namespace.
///
/// The supervisor needs its own /proc mount owned by the current user
/// namespace so that /proc/<pid>/mem access works. The host's original
/// /proc is owned by init_user_ns and the kernel denies mem access from
/// child user namespaces through that mount.
///
/// We unshare the mount namespace first to avoid affecting the worker's
/// filesystem view (the worker will do its own pivot_root later).
fn mount_supervisor_proc() {
    // Isolate mount namespace so our /proc mount doesn't leak to the worker.
    if let Err(e) = unshare(CloneFlags::CLONE_NEWNS) {
        tracing::warn!(error = %e, "failed to unshare mount ns for supervisor /proc");
        return;
    }

    // Mount a fresh procfs over /proc.
    let proc_cstr = c"/proc";
    let proc_type = c"proc";
    let ret = unsafe {
        libc::mount(
            proc_type.as_ptr(),
            proc_cstr.as_ptr(),
            proc_type.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            "failed to mount /proc for supervisor"
        );
    } else {
        tracing::debug!("mounted supervisor /proc (owned by user namespace)");
    }
}

/// Storage for the notifier send fd.
///
/// Set by `enter_pid_namespace_supervised` in the worker child so that
/// `child_entry` can retrieve it later to send the notifier fd to the
/// PID-1 supervisor after installing the seccomp filter.
///
/// Using `Mutex<Option<_>>` because the fd is set exactly once (after fork)
/// and taken exactly once (when installing the notifier filter).
static NOTIFIER_SEND_FD: std::sync::Mutex<Option<OwnedFd>> = std::sync::Mutex::new(None);

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
