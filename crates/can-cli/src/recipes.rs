use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use can_policy::config::expand_env_vars;
use can_policy::profile::baseline_search_dirs;
use can_policy::{RecipeFile, SeccompProfile, walk_recipes};

/// Category derived from the recipe's parent directory relative to the
/// recipe search dir. Top-level recipes get `"core"`.
fn category_for(path: &Path, search_dir: &Path) -> String {
    path.strip_prefix(search_dir)
        .ok()
        .and_then(|rel| rel.parent())
        .and_then(|parent| parent.components().next())
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "core".to_string())
}

/// Discover all recipe files across the search path.
///
/// Returns `(path, category, RecipeFile)` triples. Infrastructure recipes
/// (`default.toml`, `base.toml`, `checksums.toml`) are filtered out by
/// `walk_recipes`. Files that fail to parse are skipped with a warning.
fn discover() -> Vec<(PathBuf, String, RecipeFile)> {
    let mut out = Vec::new();
    for dir in baseline_search_dirs() {
        for path in walk_recipes(&dir) {
            let category = category_for(&path, &dir);
            match RecipeFile::from_file(&path) {
                Ok(recipe) => out.push((path, category, recipe)),
                Err(e) => {
                    tracing::warn!("skipping {}: {e}", path.display());
                }
            }
        }
    }
    out
}

fn print_recipe_entry(path: &Path, recipe: &RecipeFile) {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");
    let name = recipe.display_name(stem);
    let desc = recipe.description();
    let extras = format_syscall_extras(&recipe.syscalls);
    let prefixes = recipe.match_prefixes();

    if desc.is_empty() {
        println!("  {name:<24} {extras:<30} {}", path.display());
    } else {
        println!(
            "  {name:<24} {desc}\n  {:<24} {extras:<30} {}",
            "",
            path.display()
        );
    }

    if !prefixes.is_empty() {
        println!("  {:<24} match: {}", "", prefixes.join(", "));
    }
}

/// Execute the `can recipe list` command.
///
/// Lists discovered recipes from the search path, grouped by category
/// (the parent directory under the search root), followed by information
/// about the default seccomp baseline and its source.
pub fn list() -> Result<i32> {
    let all = discover();

    let mut by_category: BTreeMap<String, Vec<&(PathBuf, String, RecipeFile)>> = BTreeMap::new();
    for entry in &all {
        by_category.entry(entry.1.clone()).or_default().push(entry);
    }

    println!("Recipes:\n");
    if by_category.is_empty() {
        println!("  (none found)");
    } else {
        for (category, entries) in &by_category {
            println!("[{category}]");
            for (path, _cat, recipe) in entries {
                print_recipe_entry(path, recipe);
            }
            println!();
        }
    }

    println!("Search path:");
    for dir in baseline_search_dirs() {
        let exists = dir.is_dir();
        let marker = if exists { "+" } else { " " };
        println!("  {marker} {}", dir.display());
    }

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

/// Execute the `can recipe explain` command.
///
/// Shows a user-friendly breakdown of a recipe's declared paths,
/// highlighting which paths exist on the host and separating read-only
/// from writable mounts.
pub fn explain(recipe_args: &[String]) -> Result<i32> {
    use crate::commands::resolve_recipe_path;

    for arg in recipe_args {
        let path = resolve_recipe_path(arg)?;
        let recipe = RecipeFile::from_file(&path)
            .map_err(|e| anyhow::anyhow!("loading recipe {}: {e}", path.display()))?;

        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        let name = recipe.display_name(stem);
        let desc = recipe.description();

        println!("{name}");
        if !desc.is_empty() {
            println!("  {desc}");
        }
        println!("  source: {}", path.display());
        println!();

        // Filesystem
        let fs = &recipe.filesystem;
        if !fs.allow.is_empty() || !fs.allow_write.is_empty() || !fs.deny.is_empty() {
            println!("  Filesystem:");
            print_path_section("  read-only", &fs.allow);
            print_path_section("  writable ", &fs.allow_write);
            print_path_section("  denied   ", &fs.deny);
            println!();
        }

        // Per-destination contracts.
        if !recipe.hosts.is_empty() {
            println!("  Hosts:");
            for h in &recipe.hosts {
                println!("    {}", h.domain);
            }
            println!();
        }

        // Environment
        if !recipe.process.env_passthrough.is_empty() {
            println!("  Environment passthrough:");
            for var in &recipe.process.env_passthrough {
                let status = match std::env::var(var) {
                    Ok(_) => "set",
                    Err(_) => "unset",
                };
                println!("    {var:<30} ({status})");
            }
            println!();
        }

        // Match prefixes
        let prefixes = recipe.match_prefixes();
        if !prefixes.is_empty() {
            println!("  Auto-detection prefixes:");
            for prefix in prefixes {
                let expanded = expand_env_vars(prefix);
                if expanded == *prefix {
                    println!("    {prefix}");
                } else {
                    let exists = Path::new(&expanded).exists();
                    let marker = if exists { "+" } else { "-" };
                    println!("    {prefix}  ->  {expanded} [{marker}]");
                }
            }
            println!();
        }
    }

    Ok(0)
}

/// Execute the `can recipe suggest` command.
///
/// Takes a command line, resolves the binary, and recommends recipes
/// whose name matches the binary basename or whose `match_prefix`
/// covers the resolved binary path.
pub fn suggest(command: &[String]) -> Result<i32> {
    let cmd = command
        .first()
        .ok_or_else(|| anyhow::anyhow!("no command specified"))?;

    let resolved = which(cmd);
    let basename = resolved
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or(cmd);

    if let Some(ref p) = resolved {
        tracing::debug!(command = cmd, resolved = %p.display(), "resolved command binary");
    }

    let all = discover();
    let mut suggestions: Vec<String> = Vec::new();

    for (path, _category, recipe) in &all {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");

        // Match by recipe stem → command basename (recipe "npm" matches `npm`).
        if stem == basename {
            suggestions.push(stem.to_string());
            continue;
        }

        // Match by match_prefix against the resolved binary path.
        if let Some(ref resolved_path) = resolved {
            let resolved_str = resolved_path.to_string_lossy();
            for prefix in recipe.match_prefixes_expanded() {
                if resolved_str.starts_with(&prefix) {
                    suggestions.push(stem.to_string());
                    break;
                }
            }
        }
    }

    suggestions.dedup();

    if suggestions.is_empty() {
        println!("No matching recipes found for `{cmd}`.");
        println!("\nRun `can recipe list` to see all available recipes.");
    } else {
        let quoted: Vec<_> = suggestions.iter().map(|s| format!("\"{s}\"")).collect();
        println!("recipes = [{}]", quoted.join(", "));
    }

    Ok(0)
}

fn print_path_section(label: &str, paths: &[PathBuf]) {
    for (i, raw_path) in paths.iter().enumerate() {
        let raw = raw_path.to_string_lossy();
        let expanded = expand_env_vars(&raw);
        let exists = Path::new(&expanded).exists();
        let marker = if exists { "+" } else { "-" };

        let prefix = if i == 0 { label } else { "           " };

        if expanded == *raw {
            println!("    {prefix}  [{marker}] {raw}");
        } else {
            println!("    {prefix}  [{marker}] {raw}  ->  {expanded}");
        }
    }
}

fn which(cmd: &str) -> Option<PathBuf> {
    if cmd.contains('/') {
        let p = PathBuf::from(cmd);
        if p.is_file() {
            return Some(p);
        }
        return None;
    }

    let path_var = std::env::var("PATH").ok()?;
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(cmd);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
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
