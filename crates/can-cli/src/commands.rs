use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use can_policy::profile::baseline_search_dirs;
use can_policy::{RecipeFile, SandboxConfig, SeccompProfile, resolve_base};
use can_sandbox::SandboxOpts;
use can_sandbox::capabilities::KernelCapabilities;
use can_sandbox::mac::{self, PolicyStatus};

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

/// Execute the `can recipe show` command.
///
/// Loads and merges all recipes (same as `can run`), resolves to a
/// `SandboxConfig`, then serializes the fully resolved config as TOML
/// to stdout. The output is valid TOML that can be saved as a standalone
/// recipe file.
pub fn show(recipe_args: &[String], command: Vec<String>) -> Result<i32> {
    let cmd_name = command.first().map(|s| s.as_str());
    let mut config = load_recipes(recipe_args, cmd_name)?;

    // Resolve Option fields to their effective values so the output is
    // fully explicit — no hidden defaults.
    config.network.deny_all = Some(config.network.deny_all());
    config.syscalls.seccomp_mode = Some(config.syscalls.seccomp_mode());

    let toml_str =
        toml::to_string_pretty(&config).context("serializing resolved config to TOML")?;
    print!("{toml_str}");
    Ok(0)
}

/// Execute the `can run` command.
pub fn run(
    recipe_args: &[String],
    monitor: bool,
    strict: bool,
    port_args: &[String],
    command: Vec<String>,
) -> Result<i32> {
    let cmd_name = command.first().map(|s| s.as_str());
    let mut config = load_recipes(recipe_args, cmd_name)?;

    // Apply CLI --port flags (merged with any recipe-defined ports).
    for port_str in port_args {
        let mapping = can_policy::PortMapping::parse(port_str)
            .map_err(|e| anyhow::anyhow!("invalid port spec '{port_str}': {e}"))?;
        config.network.ports.push(mapping);
    }

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

    // MAC policy status.
    let backend = mac::active_backend();
    match &backend {
        Some(b) => {
            let status = b.policy_status();
            let mac_name = b.name();
            match &status {
                PolicyStatus::NotNeeded => {
                    println!("  {mac_name} policy: not needed (userns unrestricted)");
                }
                PolicyStatus::NotInstalled => {
                    println!("  {mac_name} policy: NOT INSTALLED");
                    println!(
                        "                    Run `sudo can setup` to enable filesystem isolation"
                    );
                }
                PolicyStatus::Installed { bin_path } => {
                    println!("  {mac_name} policy: installed ({bin_path})");
                }
                PolicyStatus::WrongPath {
                    installed_path,
                    current_path,
                } => {
                    println!("  {mac_name} policy: WRONG PATH");
                    println!("                    Installed for: {installed_path}");
                    println!("                    Current binary: {current_path}");
                    println!("                    Run `sudo can setup` to update");
                }
                PolicyStatus::Stale { bin_path } => {
                    println!("  {mac_name} policy: OUTDATED ({bin_path})");
                    println!(
                        "                    Run `sudo can setup` to update to latest version"
                    );
                }
            }
        }
        None => {
            println!("  MAC system:      none detected (AppArmor/SELinux not active)");
            println!("                   No policy installation needed");
        }
    }

    // Check network tooling.
    if can_net::pasta::is_available() {
        println!("  pasta:           available");
    } else {
        println!("  pasta:           NOT FOUND (needed for filtered network mode)");
        println!("                   Install with: sudo apt install passt");
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

        let policy_status = backend.as_ref().map(|b| b.policy_status());
        if matches!(policy_status, Some(PolicyStatus::NotInstalled)) {
            let mac_name = backend.as_ref().map(|b| b.name()).unwrap_or("MAC");
            println!("  Note: filesystem isolation requires {mac_name} policy.");
            println!("  Run: sudo can setup");
        }
        if matches!(policy_status, Some(PolicyStatus::Stale { .. })) {
            let mac_name = backend.as_ref().map(|b| b.name()).unwrap_or("MAC");
            println!("  Note: {mac_name} policy is outdated.");
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
pub fn setup(remove: bool, force: bool) -> Result<i32> {
    if remove {
        return setup_remove();
    }

    // Detect the active MAC backend.
    let backend = match mac::active_backend() {
        Some(b) => b,
        None => {
            println!("No MAC system detected (neither AppArmor nor SELinux is active).");
            println!("Canister works without a security policy on this system.");
            println!("Filesystem isolation is available natively.");
            return Ok(0);
        }
    };

    let mac_name = backend.name();

    // Check if setup is needed.
    let status = backend.policy_status();
    match &status {
        PolicyStatus::NotNeeded => {
            println!("{mac_name} does not restrict unprivileged user namespaces on this system.");
            println!("No policy installation needed — filesystem isolation works natively.");
            return Ok(0);
        }
        PolicyStatus::Installed { bin_path } if !force => {
            println!("{mac_name} policy is already installed and up to date for: {bin_path}");
            println!("Filesystem isolation should work. Run `can check` to verify.");
            println!("\nTo force reinstall: sudo can setup --force");
            return Ok(0);
        }
        PolicyStatus::Installed { bin_path } => {
            println!("Force reinstalling {mac_name} policy for: {bin_path}");
        }
        PolicyStatus::Stale { bin_path } => {
            println!(
                "{mac_name} policy for {bin_path} is outdated — updating to latest version..."
            );
        }
        PolicyStatus::WrongPath {
            installed_path,
            current_path,
        } => {
            println!("{mac_name} policy is installed but for a different binary path.");
            println!("  Installed: {installed_path}");
            println!("  Current:   {current_path}");
            println!("Updating policy...");
        }
        PolicyStatus::NotInstalled => {
            println!("{mac_name} restricts unprivileged user namespaces on this system.");
            println!("Installing Canister {mac_name} policy to enable filesystem isolation...");
        }
    }

    // Resolve the binary path.
    let bin_path = mac::resolve_bin_path().ok_or_else(|| {
        anyhow::anyhow!(
            "could not determine path to `can` binary. \
             Ensure it is installed or run from a known location."
        )
    })?;

    println!("Binary path: {bin_path}");

    // Generate the policy for review.
    let new_policy = backend.generate_policy(&bin_path);

    // Interactive mode: show the policy and ask for confirmation.
    let interactive = std::io::stdout().is_terminal();

    if interactive {
        // Show the existing policy diff if updating.
        let policy_path = backend.policy_path();
        if let Ok(existing) = std::fs::read_to_string(policy_path) {
            println!("\n--- Policy diff ({policy_path}) ---");
            print_unified_diff(&existing, &new_policy);
            println!("--- End diff ---\n");
        } else {
            println!("\n--- New {mac_name} policy ---");
            println!("{new_policy}");
            println!("--- End policy ---\n");
        }

        if !confirm("Install this policy?")? {
            println!("Aborted. No changes were made.");
            return Ok(1);
        }
    }

    // Install the policy.
    match backend.install_policy(&bin_path) {
        Ok(()) => {
            println!("\n{mac_name} policy installed successfully.");
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

/// Remove the Canister MAC policy.
fn setup_remove() -> Result<i32> {
    let backend = match mac::active_backend() {
        Some(b) => b,
        None => {
            println!("No MAC system detected — nothing to remove.");
            return Ok(0);
        }
    };

    let mac_name = backend.name();
    let status = backend.policy_status();

    match &status {
        PolicyStatus::NotInstalled | PolicyStatus::NotNeeded => {
            println!("No Canister {mac_name} policy is installed.");
            return Ok(0);
        }
        PolicyStatus::Installed { .. }
        | PolicyStatus::WrongPath { .. }
        | PolicyStatus::Stale { .. } => {}
    }

    // Interactive confirmation for removal.
    let interactive = std::io::stdout().is_terminal();
    if interactive {
        println!("This will remove the Canister {mac_name} policy.");
        println!("Filesystem isolation will be disabled until the policy is reinstalled.");
        if !confirm("Remove the policy?")? {
            println!("Aborted. No changes were made.");
            return Ok(1);
        }
    }

    match backend.remove_policy() {
        Ok(()) => {
            println!("Canister {mac_name} policy removed.");
            println!("Filesystem isolation will be disabled until the policy is reinstalled.");
            Ok(0)
        }
        Err(e) => {
            eprintln!("{e}");
            Ok(1)
        }
    }
}

/// Ask the user for confirmation (Y/n). Returns true if confirmed.
///
/// Non-interactive environments (piped stdin) always return true.
fn confirm(prompt: &str) -> Result<bool> {
    if !std::io::stdin().is_terminal() {
        return Ok(true);
    }

    eprint!("{prompt} [Y/n] ");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("reading user input")?;

    let trimmed = input.trim().to_lowercase();
    Ok(trimmed.is_empty() || trimmed == "y" || trimmed == "yes")
}

/// Print a minimal unified diff between two strings.
///
/// This is intentionally simple — no external crate needed.
fn print_unified_diff(old: &str, new: &str) {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    // Simple line-by-line comparison (not a true LCS diff, but good enough
    // for policy files which are relatively short and structured).
    let max_len = old_lines.len().max(new_lines.len());
    let mut has_changes = false;

    for i in 0..max_len {
        let old_line = old_lines.get(i).copied();
        let new_line = new_lines.get(i).copied();

        match (old_line, new_line) {
            (Some(o), Some(n)) if o == n => {
                println!(" {o}");
            }
            (Some(o), Some(n)) => {
                println!("-{o}");
                println!("+{n}");
                has_changes = true;
            }
            (Some(o), None) => {
                println!("-{o}");
                has_changes = true;
            }
            (None, Some(n)) => {
                println!("+{n}");
                has_changes = true;
            }
            (None, None) => {}
        }
    }

    if !has_changes {
        println!("(no changes)");
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
