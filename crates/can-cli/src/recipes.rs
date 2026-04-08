use std::path::PathBuf;

use anyhow::Result;

use can_policy::profile::baseline_search_dirs;
use can_policy::{RecipeFile, SeccompProfile};

/// Discover all `.toml` recipe files across search directories.
///
/// Returns `(path, RecipeFile)` pairs. `default.toml` and `base.toml` are
/// excluded — they are infrastructure recipes (always loaded), not regular
/// user-facing recipes. Files that fail to parse are skipped with a warning.
fn discover() -> Vec<(PathBuf, RecipeFile)> {
    let mut recipes = Vec::new();

    for dir in baseline_search_dirs() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue, // directory doesn't exist or unreadable
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
/// information about the default seccomp baseline and its source.
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

            let extras = format_syscall_extras(&recipe.syscalls);
            let prefixes = recipe.match_prefixes();

            if desc.is_empty() {
                println!("  {name:<20} {extras:<30} {}", path.display());
            } else {
                println!(
                    "  {name:<20} {desc}\n  {:<20} {extras:<30} {}",
                    "",
                    path.display()
                );
            }

            if !prefixes.is_empty() {
                println!("  {:<20} match: {}", "", prefixes.join(", "));
            }
        }
    }

    println!("\nSearch path:");
    for dir in baseline_search_dirs() {
        let exists = dir.is_dir();
        let marker = if exists { "+" } else { " " };
        println!("  {marker} {}", dir.display());
    }

    // --- Default baseline ---
    match SeccompProfile::resolve_baseline() {
        Ok(resolved) => {
            println!(
                "\nDefault baseline: {} allowed, {} denied syscalls",
                resolved.profile.allow_syscalls.len(),
                resolved.profile.deny_syscalls.len(),
            );
            println!("  Source: {}", resolved.source);
        }
        Err(e) => {
            println!("\nDefault baseline: ERROR resolving — {e}");
        }
    }
    println!("  Customize per-recipe with [syscalls] allow_extra / deny_extra");

    Ok(0)
}

/// Format the syscall extras for display in recipe listing.
fn format_syscall_extras(syscalls: &can_policy::SyscallConfig) -> String {
    let mut parts = Vec::new();
    if !syscalls.allow_extra.is_empty() {
        parts.push(format!("+{}", syscalls.allow_extra.join(",")));
    }
    if !syscalls.deny_extra.is_empty() {
        parts.push(format!("-{}", syscalls.deny_extra.join(",")));
    }
    if parts.is_empty() {
        "(default syscalls)".to_string()
    } else {
        parts.join(" ")
    }
}
