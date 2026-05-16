use std::path::{Path, PathBuf};

use anyhow::Result;

use can_policy::config::expand_env_vars;
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
        scan_dir(&dir, &mut recipes);

        let tools_dir = dir.join("tools");
        scan_dir(&tools_dir, &mut recipes);
    }

    recipes
}

fn scan_dir(dir: &Path, out: &mut Vec<(PathBuf, RecipeFile)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
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
            Ok(recipe) => out.push((path, recipe)),
            Err(e) => {
                tracing::warn!("skipping {}: {e}", path.display());
            }
        }
    }
}

fn is_tool_recipe(recipe: &RecipeFile) -> bool {
    recipe.display_name("").starts_with("tool:")
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
/// Lists discovered recipes from the search path, grouped into regular
/// recipes and tool shortcuts, followed by information about the default
/// seccomp baseline and its source.
pub fn list() -> Result<i32> {
    let all = discover();

    let (tools, regular): (Vec<_>, Vec<_>) = all.iter().partition(|(_, r)| is_tool_recipe(r));

    // --- Regular recipes ---
    println!("Recipes:\n");
    if regular.is_empty() {
        println!("  (none found)");
    } else {
        for (path, recipe) in &regular {
            print_recipe_entry(path, recipe);
        }
    }

    // --- Tool shortcuts ---
    println!("\nTool shortcuts:\n");
    if tools.is_empty() {
        println!("  (none found — run `can init` to install curated tool recipes)");
    } else {
        for (path, recipe) in &tools {
            print_recipe_entry(path, recipe);
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

        // Network
        if !recipe.network.allow_domains.is_empty() {
            println!("  Allowed domains:");
            for domain in &recipe.network.allow_domains {
                println!("    {domain}");
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
/// Takes a command line, resolves the binary, and recommends tool recipes
/// based on binary basename matching known `tool:*` recipe names and
/// `match_prefix` on the resolved binary path.
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

    for (path, recipe) in &all {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let name = recipe.display_name(stem);

        // Match by tool name → command basename (tool:npm matches `npm`)
        if let Some(tool_name) = name.strip_prefix("tool:") {
            if tool_name == basename {
                suggestions.push(tool_name.to_string());
                continue;
            }
        }

        // Match by match_prefix against the resolved binary path
        if let Some(ref resolved_path) = resolved {
            let resolved_str = resolved_path.to_string_lossy();
            for prefix in recipe.match_prefixes_expanded() {
                if resolved_str.starts_with(&prefix) {
                    if let Some(tool_name) = name.strip_prefix("tool:") {
                        suggestions.push(tool_name.to_string());
                    } else {
                        suggestions.push(name.clone());
                    }
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
        let tool_suggestions: Vec<_> = suggestions
            .iter()
            .filter(|s| {
                all.iter().any(|(_, r)| {
                    r.display_name("")
                        .strip_prefix("tool:")
                        .is_some_and(|t| t == s.as_str())
                })
            })
            .collect();
        let other_suggestions: Vec<_> = suggestions
            .iter()
            .filter(|s| !tool_suggestions.contains(s))
            .collect();

        if !tool_suggestions.is_empty() {
            let quoted: Vec<_> = tool_suggestions
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect();
            println!("tools = [{}]", quoted.join(", "));
        }
        if !other_suggestions.is_empty() {
            let quoted: Vec<_> = other_suggestions
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect();
            println!("recipes = [{}]", quoted.join(", "));
        }
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
