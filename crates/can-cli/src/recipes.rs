use std::path::PathBuf;

use anyhow::Result;

use can_policy::{RecipeFile, SeccompProfile};

/// Directories searched for recipe files, in order of priority.
///
/// 1. `./recipes/` — project-local recipes
/// 2. `$XDG_CONFIG_HOME/canister/recipes/` — per-user recipes
/// 3. `/etc/canister/recipes/` — system-wide recipes
fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("recipes")];

    // XDG_CONFIG_HOME, defaulting to ~/.config
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        dirs.push(PathBuf::from(xdg).join("canister/recipes"));
    } else if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".config/canister/recipes"));
    }

    dirs.push(PathBuf::from("/etc/canister/recipes"));
    dirs
}

/// Discover all `.toml` recipe files across search directories.
///
/// Returns `(path, RecipeFile)` pairs. Files that fail to parse are
/// skipped with a warning (tracing).
fn discover() -> Vec<(PathBuf, RecipeFile)> {
    let mut recipes = Vec::new();

    for dir in search_dirs() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue, // directory doesn't exist or unreadable
        };

        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        paths.sort();

        for path in paths {
            match RecipeFile::from_file(&path) {
                Ok(recipe) => recipes.push((path, recipe)),
                Err(e) => {
                    tracing::warn!("skipping {}: {e}", path.display());
                }
            }
        }
    }

    recipes
}

/// Execute the `can recipes` command.
///
/// Lists discovered recipes from the search path, followed by
/// built-in baselines (the raw seccomp profiles).
pub fn list() -> Result<i32> {
    let recipes = discover();

    // --- Discovered recipes ---
    println!("Discovered recipes:\n");

    if recipes.is_empty() {
        println!("  (none found)");
    } else {
        for (path, recipe) in &recipes {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");
            let name = recipe.display_name(stem);
            let desc = recipe.description();
            let baseline = recipe.baseline_name();

            if desc.is_empty() {
                println!("  {name:<20} baseline={baseline:<10} {}", path.display());
            } else {
                println!(
                    "  {name:<20} {desc}\n  {:<20} baseline={baseline:<10} {}",
                    "",
                    path.display()
                );
            }
        }
    }

    println!("\nSearch path:");
    for dir in search_dirs() {
        let exists = dir.is_dir();
        let marker = if exists { "✓" } else { " " };
        println!("  {marker} {}", dir.display());
    }

    // --- Built-in baselines ---
    println!("\nBuilt-in baselines (seccomp profiles):\n");
    for name in SeccompProfile::builtin_names() {
        let profile = SeccompProfile::builtin(name).unwrap();
        println!(
            "  {:<12} {} ({} allowed, {} denied syscalls)",
            profile.name,
            profile.description,
            profile.allow_syscalls.len(),
            profile.deny_syscalls.len(),
        );
    }

    Ok(0)
}
