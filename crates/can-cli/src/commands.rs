use std::path::PathBuf;

use anyhow::{Context, Result};

use can_policy::profile::baseline_search_dirs;
use can_policy::{RecipeFile, SandboxConfig, SeccompProfile};
use can_sandbox::SandboxOpts;
use can_sandbox::capabilities::KernelCapabilities;
use can_sandbox::setup::{self, ProfileStatus};

/// Resolve a recipe argument to a filesystem path.
///
/// Rules:
/// - If the argument contains `/` or ends with `.toml`, treat as a file path.
/// - Otherwise, search for `{name}.toml` across `baseline_search_dirs()`.
///
/// Returns the resolved path, or an error if the name is not found.
fn resolve_recipe_path(arg: &str) -> Result<PathBuf> {
    // Treat as file path if it contains a separator or ends with .toml.
    if arg.contains('/') || arg.ends_with(".toml") {
        let path = PathBuf::from(arg);
        anyhow::ensure!(path.exists(), "recipe file not found: {}", path.display());
        return Ok(path);
    }

    // Name-based lookup: search for {name}.toml in search dirs.
    let filename = format!("{arg}.toml");
    for dir in baseline_search_dirs() {
        let candidate = dir.join(&filename);
        if candidate.is_file() {
            tracing::debug!(name = arg, path = %candidate.display(), "resolved recipe by name");
            return Ok(candidate);
        }
    }

    anyhow::bail!(
        "recipe '{arg}' not found. Searched for '{filename}' in:\n{}",
        baseline_search_dirs()
            .iter()
            .map(|d| format!("  {}", d.display()))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// Load and merge all recipe arguments into a single `SandboxConfig`.
///
/// Recipes are merged left-to-right using `RecipeFile::merge()`.
fn load_recipes(recipe_args: &[String]) -> Result<SandboxConfig> {
    if recipe_args.is_empty() {
        tracing::info!("no recipe specified, using default deny-all policy");
        return Ok(SandboxConfig::default_deny());
    }

    let mut merged: Option<RecipeFile> = None;

    for arg in recipe_args {
        let path = resolve_recipe_path(arg)?;
        let recipe = RecipeFile::from_file(&path)
            .with_context(|| format!("loading recipe: {}", path.display()))?;

        tracing::info!(
            recipe = recipe.display_name(
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
            ),
            path = %path.display(),
            "loaded recipe"
        );

        merged = Some(match merged {
            Some(base) => base.merge(recipe),
            None => recipe,
        });
    }

    merged
        .expect("recipe_args was non-empty")
        .into_sandbox_config()
        .context("resolving merged recipe")
}

/// Execute the `can run` command.
pub fn run(
    recipe_args: &[String],
    monitor: bool,
    strict: bool,
    command: Vec<String>,
) -> Result<i32> {
    let config = load_recipes(recipe_args)?;

    // CLI --strict flag overrides config (can only tighten, never loosen).
    let effective_strict = strict || config.strict;

    if monitor && effective_strict {
        anyhow::bail!("--monitor and --strict are mutually exclusive");
    }

    if effective_strict {
        tracing::warn!("STRICT MODE: all setup failures are fatal, seccomp uses KILL_PROCESS");
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
        strict: effective_strict,
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

    // Check cgroup v2 delegation.
    if caps.cgroups_v2 {
        if can_sandbox::cgroups::is_available() {
            println!("  cgroups v2:      available and delegated (memory/CPU limits work)");
        } else {
            println!("  cgroups v2:      available but NOT delegated to current user");
            println!("                   memory_mb and cpu_percent limits will be unavailable");
        }
    } else {
        println!("  cgroups v2:      NOT available (no resource limits)");
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

/// Print a preview of the active policy before running in monitor mode.
///
/// Helps the user understand what enforcement points will be observed.
fn print_monitor_policy_preview(config: &SandboxConfig) {
    eprintln!("\n--- Monitor Mode: Active Policy Preview ---");

    // Seccomp baseline + overrides.
    match SeccompProfile::resolve_baseline() {
        Ok(resolved) => {
            let n_allow = resolved.profile.allow_syscalls.len() + config.syscalls.allow_extra.len();
            let n_deny = resolved.profile.deny_syscalls.len() + config.syscalls.deny_extra.len();
            eprintln!("  seccomp baseline: default ({n_allow} allowed, {n_deny} denied syscalls)");
            eprintln!("  baseline source: {}", resolved.source);
        }
        Err(e) => {
            eprintln!("  seccomp baseline: ERROR resolving — {e}");
        }
    }
    if !config.syscalls.allow_extra.is_empty() {
        eprintln!("  allow_extra:     {:?}", config.syscalls.allow_extra);
    }
    if !config.syscalls.deny_extra.is_empty() {
        eprintln!("  deny_extra:      {:?}", config.syscalls.deny_extra);
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
        eprintln!("  Tip: Using default deny-all policy. Consider creating a recipe file");
        eprintln!("  with appropriate allow lists based on the observations above.");
    }

    eprintln!("--- End Monitor Summary ---");
}
