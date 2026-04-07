use std::path::PathBuf;

use anyhow::{Context, Result};

use can_policy::{SandboxConfig, SeccompProfile};
use can_sandbox::SandboxOpts;
use can_sandbox::capabilities::KernelCapabilities;
use can_sandbox::setup::{self, ProfileStatus};

/// Execute the `can run` command.
pub fn run(
    config_path: Option<PathBuf>,
    profile: Option<String>,
    monitor: bool,
    command: Vec<String>,
) -> Result<i32> {
    let config = match config_path {
        Some(ref path) => SandboxConfig::from_file(path)
            .with_context(|| format!("loading config: {}", path.display()))?,
        None => {
            tracing::info!("no config file specified, using default deny-all policy");
            SandboxConfig::default_deny()
        }
    };

    // Override profile if specified on command line.
    let mut config = config;
    if let Some(profile_name) = profile {
        config.profile.name = profile_name;
    }

    if monitor {
        tracing::warn!(
            "MONITOR MODE: policy enforcement is relaxed — violations are logged, not enforced"
        );
        print_monitor_policy_preview(&config);
    }

    let (cmd, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no command specified"))?;

    let opts = SandboxOpts {
        command: cmd.clone(),
        args: args.to_vec(),
        config,
        monitor,
    };

    let exit_code = can_sandbox::run(&opts)?;

    if monitor {
        print_monitor_exit_summary(exit_code, &opts.config);
    }

    Ok(exit_code)
}

/// Execute the `can check` command.
pub fn check() -> Result<i32> {
    let caps = KernelCapabilities::detect();
    println!("{}", caps.summary());

    // AppArmor profile status.
    let profile_status = setup::detect_profile_status();
    match &profile_status {
        ProfileStatus::NotNeeded => {
            println!("  AppArmor profile: not needed (userns unrestricted)");
        }
        ProfileStatus::NotInstalled => {
            println!("  AppArmor profile: NOT INSTALLED");
            println!("                    Run `sudo can setup` to enable filesystem isolation");
        }
        ProfileStatus::Installed { bin_path } => {
            println!("  AppArmor profile: installed ({})", bin_path);
        }
        ProfileStatus::WrongPath {
            installed_path,
            current_path,
        } => {
            println!("  AppArmor profile: WRONG PATH");
            println!("                    Installed for: {installed_path}");
            println!("                    Current binary: {current_path}");
            println!("                    Run `sudo can setup` to update");
        }
    }

    // Check network tooling.
    if can_net::slirp::is_available() {
        println!("  slirp4netns:     available");
    } else {
        println!("  slirp4netns:     NOT FOUND (needed for filtered network mode)");
        println!("                   Install with: sudo apt install slirp4netns");
    }

    // Check seccomp support.
    if can_sandbox::seccomp::is_supported() {
        println!("  seccomp:         supported");
    } else {
        println!("  seccomp:         NOT SUPPORTED (syscall filtering will be unavailable)");
    }

    // Process control checks.
    if caps.pid_namespaces {
        println!("  PID namespaces:  available (process isolation active)");
    } else {
        println!("  PID namespaces:  NOT available (process isolation degraded)");
    }
    println!("  RLIMIT_NPROC:    available (max_pids enforcement)");
    println!("  env_passthrough: available (environment filtering)");

    if caps.meets_minimum() {
        println!("\nCanister can run on this system.");
        if matches!(profile_status, ProfileStatus::NotInstalled) {
            println!("  Note: filesystem isolation requires AppArmor profile.");
            println!("  Run: sudo can setup");
        }
        Ok(0)
    } else {
        println!("\nWARNING: This system does not meet minimum requirements.");
        println!("Canister requires at least user namespaces and PID namespaces.");
        Ok(1)
    }
}

/// Execute the `can setup` command.
pub fn setup(remove: bool) -> Result<i32> {
    if remove {
        return setup_remove();
    }

    // Check if setup is needed.
    let status = setup::detect_profile_status();
    match &status {
        ProfileStatus::NotNeeded => {
            println!("AppArmor does not restrict unprivileged user namespaces on this system.");
            println!("No profile installation needed — filesystem isolation works natively.");
            return Ok(0);
        }
        ProfileStatus::Installed { bin_path } => {
            println!("AppArmor profile is already installed for: {bin_path}");
            println!("Filesystem isolation should work. Run `can check` to verify.");
            return Ok(0);
        }
        ProfileStatus::WrongPath {
            installed_path,
            current_path,
        } => {
            println!("AppArmor profile is installed but for a different binary path.");
            println!("  Installed: {installed_path}");
            println!("  Current:   {current_path}");
            println!("Updating profile...");
        }
        ProfileStatus::NotInstalled => {
            println!("AppArmor restricts unprivileged user namespaces on this system.");
            println!("Installing Canister AppArmor profile to enable filesystem isolation...");
        }
    }

    // Resolve the binary path.
    let bin_path = setup::resolve_bin_path().ok_or_else(|| {
        anyhow::anyhow!(
            "could not determine path to `can` binary. \
             Ensure it is installed or run from a known location."
        )
    })?;

    println!("Binary path: {bin_path}");

    // Install the profile.
    match setup::install_profile(&bin_path) {
        Ok(()) => {
            println!("\nAppArmor profile installed successfully.");
            println!("Filesystem isolation is now enabled.");
            println!("\nVerify with: can check");
            Ok(0)
        }
        Err(e) => {
            eprintln!("{e}");
            Ok(1)
        }
    }
}

/// Remove the Canister AppArmor profile.
fn setup_remove() -> Result<i32> {
    let status = setup::detect_profile_status();
    match &status {
        ProfileStatus::NotInstalled | ProfileStatus::NotNeeded => {
            println!("No Canister AppArmor profile is installed.");
            return Ok(0);
        }
        _ => {}
    }

    match setup::remove_profile() {
        Ok(()) => {
            println!("Canister AppArmor profile removed.");
            println!("Filesystem isolation will be disabled until the profile is reinstalled.");
            Ok(0)
        }
        Err(e) => {
            eprintln!("{e}");
            Ok(1)
        }
    }
}

/// Execute the `can profiles` command.
pub fn profiles() -> Result<i32> {
    println!("Available seccomp profiles:\n");
    for name in SeccompProfile::builtin_names() {
        let profile = SeccompProfile::builtin(name).unwrap();
        println!(
            "  {:<12} {} ({} denied syscalls)",
            profile.name,
            profile.description,
            profile.deny_syscalls.len()
        );
    }
    Ok(0)
}

/// Print a preview of the active policy before running in monitor mode.
///
/// Helps the user understand what enforcement points will be observed.
fn print_monitor_policy_preview(config: &SandboxConfig) {
    eprintln!("\n--- Monitor Mode: Active Policy Preview ---");

    // Seccomp profile.
    if let Some(profile) = SeccompProfile::builtin(&config.profile.name) {
        eprintln!(
            "  seccomp profile: {} ({} denied syscalls)",
            profile.name,
            profile.deny_syscalls.len()
        );
    } else {
        eprintln!("  seccomp profile: {} (unknown)", config.profile.name);
    }

    // allow_execve.
    if config.process.allow_execve.is_empty() {
        eprintln!("  allow_execve:    unrestricted (any command allowed)");
    } else {
        eprintln!(
            "  allow_execve:    {} allowed commands",
            config.process.allow_execve.len()
        );
    }

    // env_passthrough.
    if config.process.env_passthrough.is_empty() {
        eprintln!("  env_passthrough: empty (all env vars would be stripped)");
    } else {
        eprintln!(
            "  env_passthrough: {} variables",
            config.process.env_passthrough.len()
        );
    }

    // max_pids.
    match config.process.max_pids {
        Some(n) => eprintln!("  max_pids:        {n}"),
        None => eprintln!("  max_pids:        unlimited"),
    }

    // Network.
    let net_mode = can_net::NetworkMode::from_config(&config.network);
    eprintln!("  network:         {net_mode:?}");

    eprintln!("---\n");
}

/// Print a post-execution summary for monitor mode.
///
/// The detailed per-event logging has already been emitted via tracing
/// during sandbox setup. This summary provides a final overview and hints.
fn print_monitor_exit_summary(exit_code: i32, config: &SandboxConfig) {
    eprintln!("\n--- Monitor Summary ---");
    eprintln!("  exit code: {exit_code}");
    eprintln!();
    eprintln!("  Review MONITOR: lines above for policy violations that were relaxed.");
    eprintln!("  Seccomp LOG events (if any) appear in: journalctl -k | grep seccomp");

    // Suggest a minimal config based on what we know.
    let has_restrictions = !config.process.allow_execve.is_empty()
        || !config.process.env_passthrough.is_empty()
        || config.process.max_pids.is_some();

    if has_restrictions {
        eprintln!();
        eprintln!("  Tip: If the process ran correctly with exit code 0,");
        eprintln!("  your current policy is likely compatible. Remove --monitor to enforce.");
    } else {
        eprintln!();
        eprintln!("  Tip: Using default deny-all policy. Consider creating a config file");
        eprintln!("  with appropriate allow lists based on the observations above.");
    }

    eprintln!("--- End Monitor Summary ---");
}
