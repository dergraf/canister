use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use can_policy::config::EgressMode;
use can_policy::profile::baseline_search_dirs;
use can_policy::{
    Manifest, RecipeFile, SandboxConfig, SandboxDef, SeccompProfile, discover_manifest,
    resolve_base, walk_recipes,
};
use can_sandbox::SandboxOpts;
use can_sandbox::capabilities::KernelCapabilities;
use can_sandbox::mac::{self, PolicyStatus};

/// Resolve a recipe argument to a filesystem path.
///
/// Rules:
/// - If the argument contains `/` or ends with `.toml`, treat as a file path.
/// - Otherwise, search each `baseline_search_dirs()` entry recursively for
///   a file whose stem matches `arg`. First search dir with a match wins;
///   recipe names must be globally unique within a single search dir, so
///   two recipes with the same stem in different category subdirs of the
///   same dir is an error.
pub(crate) fn resolve_recipe_path(arg: &str) -> Result<PathBuf> {
    // Treat as file path if it contains a separator or ends with .toml.
    if arg.contains('/') || arg.ends_with(".toml") {
        let path = PathBuf::from(arg);
        anyhow::ensure!(path.exists(), "recipe file not found: {}", path.display());
        return Ok(path);
    }

    // Name-based lookup: recursively scan each search dir.
    for dir in baseline_search_dirs() {
        let mut matches: Vec<PathBuf> = walk_recipes(&dir)
            .into_iter()
            .filter(|p| p.file_stem().and_then(|s| s.to_str()) == Some(arg))
            .collect();
        match matches.len() {
            0 => continue,
            1 => {
                let path = matches.pop().ok_or_else(|| {
                    anyhow::anyhow!("internal error: expected exactly one recipe match")
                })?;
                tracing::debug!(name = arg, path = %path.display(), "resolved recipe by name");
                return Ok(path);
            }
            _ => {
                anyhow::bail!(
                    "recipe '{arg}' is ambiguous within {} — matched:\n{}\n\
                     Rename one of the files so recipe stems are unique.",
                    dir.display(),
                    matches
                        .iter()
                        .map(|p| format!("  {}", p.display()))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
        }
    }

    anyhow::bail!(
        "recipe '{arg}' not found. Searched for '{arg}.toml' recursively in:\n{}",
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
/// 2. Explicit `--recipe` arguments — merged left-to-right
///
/// The seccomp baseline (`default.toml`) is resolved separately by the
/// seccomp layer and is NOT part of this composition stack.
fn load_recipes(recipe_args: &[String], _command: Option<&str>) -> Result<SandboxConfig> {
    // 1. Start with base.toml (essential OS mounts).
    let mut merged = resolve_base().context("loading base.toml")?;
    tracing::debug!("loaded base.toml (essential OS mounts)");

    // 2. Merge explicit --recipe arguments left-to-right.
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
        tracing::debug!("loaded recipe {:?}", arg);

        merged = merged.merge(recipe);
    }

    merged
        .into_sandbox_config()
        .context("resolving merged recipe")
}

/// Load recipes for a manifest sandbox definition.
///
/// Composition order:
/// 1. `base.toml` — essential OS filesystem mounts (always loaded)
/// 2. Recipes listed in the manifest sandbox (resolved by name, left-to-right)
/// 3. Manifest overrides (filesystem, network, etc. from the sandbox definition)
fn load_manifest_recipes(def: &SandboxDef) -> Result<SandboxConfig> {
    // 1. Start with base.toml.
    let mut merged = resolve_base().context("loading base.toml")?;
    tracing::debug!("loaded base.toml (essential OS mounts)");

    // 2. Merge recipes listed in the manifest.
    for recipe_name in &def.recipes {
        let path = resolve_recipe_path(recipe_name)?;
        let recipe = RecipeFile::from_file(&path)
            .with_context(|| format!("loading recipe: {}", path.display()))?;

        tracing::info!(
            recipe = recipe.display_name(
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
            ),
            path = %path.display(),
            "loaded recipe (from manifest)"
        );

        merged = merged.merge(recipe);
    }

    // 4. Apply manifest-level overrides as the final layer.
    let overrides: can_policy::RecipeFile = def.into();
    merged = merged.merge(overrides);

    merged
        .into_sandbox_config()
        .context("resolving merged manifest recipes")
}

/// Execute the `can up` command.
///
/// Discovers `canister.toml`, resolves the named sandbox (or the first
/// defined), composes recipes, and runs the command.
pub fn up(
    name: Option<&str>,
    dry_run: bool,
    monitor: bool,
    strict: bool,
    port_args: &[String],
) -> Result<i32> {
    // Discover canister.toml by walking up from CWD.
    let cwd = std::env::current_dir().context("getting current directory")?;
    let manifest_path = discover_manifest(&cwd).ok_or_else(|| {
        anyhow::anyhow!(
            "no canister.toml found.\n\
             Searched from: {}\n\n\
             Create a canister.toml in your project root, or use `can run` for ad-hoc sandboxing.",
            cwd.display()
        )
    })?;

    tracing::info!(path = %manifest_path.display(), "loading canister.toml");
    let manifest = Manifest::from_file(&manifest_path)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;

    // Resolve sandbox name.
    let sandbox_names = manifest.sandbox_names();
    let sandbox_name = match name {
        Some(n) => {
            if manifest.get(n).is_none() {
                anyhow::bail!(
                    "sandbox '{n}' not found in {}.\nAvailable sandboxes: {}",
                    manifest_path.display(),
                    sandbox_names.join(", ")
                );
            }
            n.to_string()
        }
        None => {
            // Default to the first sandbox (alphabetically sorted).
            let first = sandbox_names
                .first()
                .ok_or_else(|| anyhow::anyhow!("no sandboxes defined in canister.toml"))?;
            tracing::info!(sandbox = first, "using default sandbox (first defined)");
            first.to_string()
        }
    };

    // SAFETY-UNWRAP: sandbox_name was just resolved from this manifest's
    // entries (either by explicit lookup or by taking the first key), so
    // get() is guaranteed to return Some.
    let def = manifest.get(&sandbox_name).unwrap();

    // Print sandbox info.
    if let Some(desc) = &def.description {
        println!("sandbox: {sandbox_name} — {desc}");
    } else {
        println!("sandbox: {sandbox_name}");
    }
    println!("command: {}", def.command);
    println!("recipes: {}", def.recipes.join(", "));
    println!();

    // Compose recipes.
    let mut config = load_manifest_recipes(def)?;

    // Auto-mask canister.toml so the sandboxed process cannot read the
    // security policy. This is the core anti-detection mechanism.
    config.filesystem.mask.push(manifest_path.clone());

    // Auto-mask .canister/ directory so local recipes are not visible
    // inside the sandbox.
    let canister_dir = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(".canister");
    if canister_dir.is_dir() {
        config.filesystem.mask.push(canister_dir);
    }

    // Apply CLI --port flags.
    for port_str in port_args {
        let mapping = can_policy::PortMapping::parse(port_str)
            .map_err(|e| anyhow::anyhow!("invalid port spec '{port_str}': {e}"))?;
        config.network.ports.push(mapping);
    }

    // CLI --strict overrides (can only tighten).
    let effective_strict = strict || config.strict;

    // Dry-run: print the resolved config and exit.
    if dry_run {
        return print_dry_run(&config, effective_strict);
    }

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

    // Parse command from the sandbox definition.
    let parts = def.command_parts();
    let (cmd, args) = parts
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty command in sandbox '{sandbox_name}'"))?;

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

/// Print the resolved policy for `can up --dry-run`.
fn print_dry_run(config: &SandboxConfig, strict: bool) -> Result<i32> {
    println!("--- Resolved Policy (dry run) ---\n");

    // Strict mode.
    println!("strict: {strict}");
    println!();

    // Filesystem.
    println!("[filesystem]");
    if !config.filesystem.read.is_empty() {
        println!("  read ({} paths):", config.filesystem.read.len());
        for p in &config.filesystem.read {
            println!("    {}", p.display());
        }
    }
    if !config.filesystem.write.is_empty() {
        println!("  write ({} paths):", config.filesystem.write.len());
        for p in &config.filesystem.write {
            println!("    {}", p.display());
        }
    }
    if !config.filesystem.deny.is_empty() {
        println!("  deny ({} paths):", config.filesystem.deny.len());
        for p in &config.filesystem.deny {
            println!("    {}", p.display());
        }
    }
    if !config.filesystem.mask.is_empty() {
        println!("  mask ({} paths):", config.filesystem.mask.len());
        for p in &config.filesystem.mask {
            println!("    {}", p.display());
        }
    }
    println!();

    // Network.
    println!("[network]");
    let egress = match config.network.egress() {
        EgressMode::None => "none",
        EgressMode::ProxyOnly => "proxy",
        EgressMode::Direct => "direct (UNSAFE: unfiltered — DLP & contracts OFF)",
    };
    println!("  egress: {egress}");
    if !config.hosts.is_empty() {
        let domains: Vec<&str> = config.hosts.iter().map(|h| h.domain.as_str()).collect();
        println!("  hosts: {domains:?}");
    }
    println!();

    // Unsafe (resolved from [unsafe]; these lower isolation).
    if !config.network.allow_ips.is_empty()
        || !config.network.ports.is_empty()
        || config.network.allow_host_loopback
        || matches!(config.network.egress(), EgressMode::Direct)
        || matches!(
            config.syscalls.seccomp_mode(),
            can_policy::config::SeccompMode::DenyList
        )
    {
        println!("[unsafe] ⚠ isolation-weakening settings active");
        if matches!(config.network.egress(), EgressMode::Direct) {
            println!("  unfiltered_egress: true (DLP + contract gates OFF)");
        }
        if config.network.allow_host_loopback {
            println!("  host_loopback: true (host 127.0.0.1 services reachable)");
        }
        if !config.network.allow_ips.is_empty() {
            println!(
                "  reachable_ips: {:?} (un-scanned egress)",
                config.network.allow_ips
            );
        }
        if !config.network.ports.is_empty() {
            println!("  expose_ports:");
            for p in &config.network.ports {
                println!("    {p}");
            }
        }
        if matches!(
            config.syscalls.seccomp_mode(),
            can_policy::config::SeccompMode::DenyList
        ) {
            println!("  seccomp_default_allow: true (default-ALLOW syscalls)");
        }
        println!();
    }

    // Process.
    println!("[process]");
    if let Some(max) = config.process.max_pids {
        println!("  max_pids: {max}");
    }
    match config.process.exec() {
        can_policy::config::ExecPolicy::Mode(m) => {
            let label = match m {
                can_policy::config::ExecMode::Any => "any (any binary may exec)",
                can_policy::config::ExecMode::EntrypointOnly => "entrypoint-only",
            };
            println!("  exec: {label}");
        }
        can_policy::config::ExecPolicy::Allow(paths) => {
            println!("  exec ({} allowed paths):", paths.len());
            for p in &paths {
                println!("    {}", p.display());
            }
        }
    }
    if !config.process.env_passthrough.is_empty() {
        println!("  env_passthrough: {:?}", config.process.env_passthrough);
    }
    println!();

    // Resources.
    println!("[resources]");
    if let Some(mb) = config.resources.memory_mb {
        println!("  memory_mb: {mb}");
    }
    if let Some(cpu) = config.resources.cpu_percent {
        println!("  cpu_percent: {cpu}");
    }
    println!();

    // Syscalls.
    println!("[syscalls]");
    println!("  seccomp_mode: {}", config.syscalls.seccomp_mode());
    if !config.syscalls.allow_extra.is_empty() {
        println!("  allow_extra: {:?}", config.syscalls.allow_extra);
    }
    if !config.syscalls.deny_extra.is_empty() {
        println!("  deny_extra: {:?}", config.syscalls.deny_extra);
    }

    // Also show the full baseline summary.
    match SeccompProfile::resolve_baseline() {
        Ok(resolved) => {
            let n_allow = resolved.profile.allow_syscalls.len() + config.syscalls.allow_extra.len();
            let n_deny = resolved.profile.deny_syscalls.len() + config.syscalls.deny_extra.len();
            println!(
                "  baseline: {} ({n_allow} allowed, {n_deny} denied)",
                resolved.source
            );
        }
        Err(e) => {
            println!("  baseline: ERROR — {e}");
        }
    }

    println!("\n--- End Resolved Policy ---");

    Ok(0)
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
    config.network.egress = Some(config.network.egress());
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

    // Auto-mask canister.toml if it exists in CWD, even for ad-hoc runs.
    // Prevents the sandboxed process from reading the security policy.
    if let Ok(cwd) = std::env::current_dir() {
        let manifest_in_cwd = cwd.join(can_policy::MANIFEST_FILENAME);
        if manifest_in_cwd.is_file() {
            config.filesystem.mask.push(manifest_in_cwd);
        }

        // Auto-mask .canister/ directory so local recipes are not visible
        // inside the sandbox.
        let canister_dir = cwd.join(".canister");
        if canister_dir.is_dir() {
            config.filesystem.mask.push(canister_dir);
        }
    }

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

    tracing::debug!("effective egress mode: {:?}", config.network.egress());

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
                    println!("  {mac_name} policy: not needed (not enforcing)");
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
pub fn setup(remove: bool, force: bool, pasta_path: Option<&str>) -> Result<i32> {
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
            println!("{mac_name} is not enforcing on this system.");
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
            println!("{mac_name} is active on this system.");
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
    let new_policy = backend.generate_policy(&bin_path, pasta_path);

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
    match backend.install_policy(&bin_path, pasta_path) {
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

    // exec policy.
    match config.process.exec() {
        can_policy::config::ExecPolicy::Mode(can_policy::config::ExecMode::Any) => {
            eprintln!("  exec:            any (any binary may exec)");
        }
        can_policy::config::ExecPolicy::Mode(can_policy::config::ExecMode::EntrypointOnly) => {
            eprintln!("  exec:            entrypoint-only");
        }
        can_policy::config::ExecPolicy::Allow(paths) => {
            eprintln!("  exec:            {} allowed paths", paths.len());
        }
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
    let net_mode = can_net::NetworkMode::from_config(&config.network, config.hosts.len());
    eprintln!("  network:         {net_mode:?}");

    // Writable paths.
    if !config.filesystem.write.is_empty() {
        eprintln!(
            "  write:           {} writable paths",
            config.filesystem.write.len()
        );
    }

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
    let has_restrictions = !matches!(
        config.process.exec(),
        can_policy::config::ExecPolicy::Mode(can_policy::config::ExecMode::Any)
    ) || !config.process.env_passthrough.is_empty()
        || config.process.max_pids.is_some();

    if has_restrictions {
        eprintln!();
        eprintln!("  Tip: If the process ran correctly with exit code 0,");
        eprintln!("  your current policy is likely compatible. Remove --monitor to enforce.");
    } else {
        eprintln!();
        eprintln!("  Tip: Using default proxy-only policy. Consider creating a recipe file");
        eprintln!("  with appropriate allow lists based on the observations above.");
    }

    eprintln!("--- End Monitor Summary ---");
}

#[cfg(test)]
mod tests {
    use super::*;

    // The path-shape branches of `resolve_recipe_path` don't depend on the
    // recipe search path, so they can be unit-tested deterministically.
    // The "happy path" lookup and ambiguity errors are covered by
    // tests/integration/t_recipes.sh which exercises real recipe trees.

    #[test]
    fn resolve_recipe_path_treats_slash_as_file_path() {
        // Path-with-slash → file-not-found error rather than a bare-name lookup.
        let err = resolve_recipe_path("./does-not-exist.toml").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("recipe file not found"),
            "expected file-not-found error, got: {msg}"
        );
    }

    #[test]
    fn resolve_recipe_path_missing_bare_name_explains_search_path() {
        let err = resolve_recipe_path("definitely-no-such-recipe").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("definitely-no-such-recipe.toml"),
            "expected filename in error, got: {msg}"
        );
        assert!(
            msg.contains("recursively"),
            "expected hint that search is recursive, got: {msg}"
        );
    }
}
