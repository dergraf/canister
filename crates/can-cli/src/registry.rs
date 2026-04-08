//! Recipe registry: download and manage community recipes.
//!
//! Supports `can init` and `can update` by shallow-cloning the canister
//! GitHub repository (via `git`) and copying `.toml` recipe files from
//! its `recipes/` directory into `$XDG_CONFIG_HOME/canister/recipes/`.
//!
//! If `git` is not available, prints manual download instructions.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

/// Default GitHub repository for recipes (same repo as canister itself).
const DEFAULT_REPO: &str = "canister-sandbox/canister";

/// Default branch to fetch from.
const DEFAULT_BRANCH: &str = "main";

/// Build the HTTPS clone URL for a GitHub repository.
fn repo_url(repo: &str) -> String {
    format!("https://github.com/{repo}.git")
}

/// Check whether `git` is available on the system.
fn has_git() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Resolve the recipe install directory.
///
/// Uses `$XDG_CONFIG_HOME/canister/recipes/` (defaulting to
/// `$HOME/.config/canister/recipes/` if `XDG_CONFIG_HOME` is unset).
pub fn recipe_install_dir() -> Result<PathBuf> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config")
    } else {
        anyhow::bail!("cannot determine config directory: neither XDG_CONFIG_HOME nor HOME is set");
    };

    Ok(base.join("canister/recipes"))
}

/// Clone the recipe repo into a temp directory, then copy `.toml` files
/// from its `recipes/` subdirectory into `dest_dir`.
///
/// Returns the list of installed recipe file names.
fn clone_and_install(dest_dir: &Path, repo: &str, branch: &str) -> Result<Vec<String>> {
    let url = repo_url(repo);

    // Shallow clone into a temp directory.
    let tmp = tempdir()?;
    let clone_dir = tmp.join("repo");

    tracing::info!(url = %url, branch = branch, "cloning recipe repository");

    let status = Command::new("git")
        .args(["clone", "--depth", "1", "--branch", branch, &url])
        .arg(&clone_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .context("failed to run git")?;

    if !status.success() {
        anyhow::bail!(
            "git clone failed (exit {}).\n\
             Repository: {url}\n\
             Branch: {branch}\n\n\
             Check that the repository exists and is accessible.",
            status.code().unwrap_or(-1)
        );
    }

    // Look for recipes/ directory in the clone.
    let recipes_dir = clone_dir.join("recipes");
    if !recipes_dir.is_dir() {
        anyhow::bail!(
            "cloned repository does not contain a recipes/ directory.\n\
             Expected: {url} to have a recipes/ folder with .toml files."
        );
    }

    // Create destination directory.
    std::fs::create_dir_all(dest_dir)
        .with_context(|| format!("creating directory: {}", dest_dir.display()))?;

    // Copy .toml files, skipping infrastructure recipes.
    let mut installed = Vec::new();

    let entries = std::fs::read_dir(&recipes_dir)
        .with_context(|| format!("reading {}", recipes_dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if !name.ends_with(".toml") {
            continue;
        }

        // Skip default.toml and base.toml — embedded in the binary.
        if name == "default.toml" || name == "base.toml" {
            tracing::debug!(file = name, "skipping infrastructure recipe");
            continue;
        }

        // Read and validate before copying.
        let content = std::fs::read_to_string(&path).with_context(|| format!("reading {name}"))?;

        let _recipe: can_policy::RecipeFile =
            toml::from_str(&content).with_context(|| format!("invalid recipe: {name}"))?;

        let dest_path = dest_dir.join(name);
        std::fs::write(&dest_path, &content)
            .with_context(|| format!("writing {}", dest_path.display()))?;

        installed.push(name.to_string());
        tracing::debug!(file = name, "installed recipe");
    }

    // Clean up temp directory (best-effort).
    let _ = std::fs::remove_dir_all(&tmp);

    installed.sort();
    Ok(installed)
}

/// Create a temporary directory and return its path.
fn tempdir() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    let name = format!("canister-recipes-{}", std::process::id());
    let path = base.join(name);

    // Remove stale temp dir if it exists (e.g., from a previous failed run).
    if path.exists() {
        let _ = std::fs::remove_dir_all(&path);
    }

    std::fs::create_dir_all(&path)
        .with_context(|| format!("creating temp directory: {}", path.display()))?;

    Ok(path)
}

/// Print manual download instructions when git is not available.
fn print_manual_instructions(repo: &str, branch: &str, dest_dir: &Path) {
    let url = format!("https://github.com/{repo}");
    println!("git is not available on this system.\n");
    println!("To install recipes manually:\n");
    println!("  1. Download the recipes from:");
    println!("     {url}/tree/{branch}/recipes\n");
    println!("  2. Copy the .toml files to:");
    println!("     {}\n", dest_dir.display());
    println!("  Or clone with git:");
    println!("     git clone --depth 1 {url}.git /tmp/canister-recipes");
    println!(
        "     cp /tmp/canister-recipes/recipes/*.toml {}",
        dest_dir.display()
    );
}

/// Execute the `can init` command.
///
/// Clones community recipes to the local config directory.
/// Falls back to manual instructions if git is unavailable.
pub fn init(repo: Option<&str>, branch: Option<&str>) -> Result<i32> {
    let repo = repo.unwrap_or(DEFAULT_REPO);
    let branch = branch.unwrap_or(DEFAULT_BRANCH);
    let dest = recipe_install_dir()?;

    println!("Installing recipes to: {}", dest.display());
    println!();

    if !has_git() {
        print_manual_instructions(repo, branch, &dest);
        return Ok(1);
    }

    let installed = clone_and_install(&dest, repo, branch)?;

    if installed.is_empty() {
        println!("No recipes found in the repository.");
        println!("Check that the repository contains a recipes/ directory with .toml files.");
    } else {
        println!("Installed {} recipes:", installed.len());
        for name in &installed {
            println!("  {name}");
        }
        println!();
        println!("Use `can recipes` to see all available recipes.");
        println!("Use `can update` to refresh from the repository.");
    }

    Ok(0)
}

/// Execute the `can update` command.
///
/// Same as `init` — re-clones and overwrites all recipes.
pub fn update(repo: Option<&str>, branch: Option<&str>) -> Result<i32> {
    let repo = repo.unwrap_or(DEFAULT_REPO);
    let branch = branch.unwrap_or(DEFAULT_BRANCH);
    let dest = recipe_install_dir()?;

    println!("Updating recipes in: {}", dest.display());
    println!();

    if !has_git() {
        print_manual_instructions(repo, branch, &dest);
        return Ok(1);
    }

    let installed = clone_and_install(&dest, repo, branch)?;

    if installed.is_empty() {
        println!("No recipes found in the repository.");
    } else {
        println!("Updated {} recipes:", installed.len());
        for name in &installed {
            println!("  {name}");
        }
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_url_default() {
        let url = repo_url(DEFAULT_REPO);
        assert_eq!(url, "https://github.com/canister-sandbox/canister.git");
    }

    #[test]
    fn repo_url_custom() {
        let url = repo_url("user/repo");
        assert_eq!(url, "https://github.com/user/repo.git");
    }

    #[test]
    fn recipe_install_dir_uses_xdg() {
        let result = recipe_install_dir();
        assert!(result.is_ok(), "recipe_install_dir failed: {result:?}");
        let dir = result.unwrap();
        assert!(
            dir.to_string_lossy().contains("canister/recipes"),
            "expected path to contain canister/recipes, got: {}",
            dir.display()
        );
    }

    #[test]
    fn git_is_available() {
        // On dev machines, git should be present.
        assert!(has_git(), "git not found — expected on dev machine");
    }
}
