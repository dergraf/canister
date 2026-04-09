use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use can_policy::profile::baseline_search_dirs;
use can_policy::{RecipeFile, SandboxConfig, SeccompProfile, resolve_base};
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
/// Composition order:
/// 1. `base.toml` — essential OS filesystem mounts (always loaded)
/// 2. Auto-detected recipes — matched by `match_prefix` against the
///    resolved command binary path
/// 3. Explicit `--recipe` arguments — merged left-to-right
///
/// The seccomp baseline (`default.toml`) is resolved separately by the
/// seccomp layer and is NOT part of this composition stack.
fn load_recipes(recipe_args: &[String], command: Option<&str>) -> Result<SandboxConfig> {
    // 1. Start with base.toml (essential OS mounts).
    let mut merged = resolve_base().context("loading base.toml")?;
    tracing::debug!("loaded base.toml (essential OS mounts)");

    // 2. Auto-detect recipes based on the resolved command path.
    if let Some(cmd) = command {
        match can_sandbox::resolve_command(cmd) {
            Ok(command_path) => {
                let auto_recipes = discover_auto_recipes(&command_path)?;
                for (path, recipe) in &auto_recipes {
                    let name = recipe.display_name(
                        path.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown"),
                    );
                    tracing::info!(
                        recipe = name,
                        path = %path.display(),
                        command = %command_path.display(),
                        "auto-detected recipe for command"
                    );
                }
                for (_path, recipe) in auto_recipes {
                    merged = merged.merge(recipe);
                }
            }
            Err(e) => {
                // Command resolution may fail (e.g., command not found).
                // Skip auto-detection; the sandbox will report the error later.
                tracing::debug!(command = cmd, error = %e, "skipping auto-detection (command resolution failed)");
            }
        }
    }

    // 3. Merge explicit --recipe arguments left-to-right.
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

        merged = merged.merge(recipe);
    }

    merged
        .into_sandbox_config()
        .context("resolving merged recipe")
}

/// Discover recipes whose `match_prefix` matches the resolved command path.
///
/// Scans all `.toml` recipe files across the recipe search path, expands
/// env vars in `match_prefix`, and returns those where the command path
/// starts with a matching prefix.
///
/// `default.toml` and `base.toml` are excluded (they serve different roles).
fn discover_auto_recipes(command_path: &Path) -> Result<Vec<(PathBuf, RecipeFile)>> {
    let mut matches = Vec::new();

    for dir in baseline_search_dirs() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|ext| ext == "toml")
                    && p.file_stem().is_some_and(|s| s != "default" && s != "base")
            })
            .collect();
        paths.sort();

        for path in paths {
            let recipe = match RecipeFile::from_file(&path) {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(path = %path.display(), error = %e, "skipping recipe (parse error)");
                    continue;
                }
            };

            let prefixes = recipe.match_prefixes_expanded();
            if prefixes.is_empty() {
                continue;
            }

            let command_str = command_path.to_string_lossy();
            let matched = prefixes
                .iter()
                .any(|prefix| command_str.starts_with(prefix));

            if matched {
                // Avoid duplicates: skip if we already matched a recipe with the same name.
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown");
                let already_matched = matches.iter().any(|(p, _): &(PathBuf, RecipeFile)| {
                    p.file_stem().and_then(|s| s.to_str()) == Some(stem)
                });
                if !already_matched {
                    matches.push((path, recipe));
                }
            }
        }
    }

    Ok(matches)
}

/// Execute the `can run` command.
pub fn run(
    recipe_args: &[String],
    monitor: bool,
    strict: bool,
    allow_degraded: bool,
    command: Vec<String>,
) -> Result<i32> {
    let cmd_name = command.first().map(|s| s.as_str());
    let config = load_recipes(recipe_args, cmd_name)?;

    // CLI --strict flag overrides config (can only tighten, never loosen).
    let effective_strict = strict || config.strict;

    // CLI --allow-degraded flag OR'd with config value.
    let effective_allow_degraded = allow_degraded || config.allow_degraded;

    if monitor && effective_strict {
        anyhow::bail!("--monitor and --strict are mutually exclusive");
    }

    if effective_strict && effective_allow_degraded {
        anyhow::bail!("--strict and --allow-degraded are mutually exclusive");
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
        allow_degraded: effective_allow_degraded,
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
