//! Recipe registry: download and manage community recipes.
//!
//! Supports `can init` and `can update` by shallow-cloning the canister
//! GitHub repository (via `git`) and copying `.toml` recipe files from
//! its `recipes/` directory into `$XDG_CONFIG_HOME/canister/recipes/`.
//!
//! Recipe integrity is verified via SHA-256 checksums. The canonical
//! checksums are embedded in the binary and also shipped in
//! `recipes/checksums.toml`. Verification can be skipped with `--no-verify`
//! (e.g., for custom/forked repos).
//!
//! If `git` is not available, prints manual download instructions.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Default GitHub repository for recipes (same repo as canister itself).
const DEFAULT_REPO: &str = "dergraf/canister";

/// Default branch to fetch from.
const DEFAULT_BRANCH: &str = "main";

/// Embedded known-good checksums (compiled into the binary).
/// These serve as the trust anchor — if the cloned repo's checksums.toml
/// differs, we use the embedded version for verification.
const EMBEDDED_CHECKSUMS: &str = include_str!("../../../recipes/checksums.toml");

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
/// When `verify` is true (default), each recipe file is checked against
/// SHA-256 checksums before installation. Checksums are loaded from the
/// embedded snapshot compiled into the binary.
///
/// Returns the list of installed recipe file names.
fn clone_and_install(
    dest_dir: &Path,
    repo: &str,
    branch: &str,
    verify: bool,
) -> Result<Vec<String>> {
    let url = repo_url(repo);

    // Load checksums for verification.
    let checksums = if verify {
        let cs = parse_checksums(EMBEDDED_CHECKSUMS)
            .context("parsing embedded checksums (this is a bug)")?;
        tracing::debug!(count = cs.len(), "loaded embedded checksums");
        Some(cs)
    } else {
        tracing::info!("checksum verification disabled (--no-verify)");
        None
    };

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

        // Verify checksum if enabled.
        if let Some(ref cs) = checksums {
            if let Some(expected) = cs.get(name) {
                let actual = sha256_hex(content.as_bytes());
                if actual != *expected {
                    anyhow::bail!(
                        "checksum mismatch for {name}:\n\
                         expected: {expected}\n\
                         actual:   {actual}\n\n\
                         The recipe file in the repository does not match the known-good checksum.\n\
                         This could indicate tampering. Use --no-verify to skip (at your own risk)."
                    );
                }
                tracing::debug!(file = name, "checksum verified");
            } else {
                tracing::warn!(
                    file = name,
                    "no checksum found for recipe — skipping verification. \
                     This recipe may be new or from a fork."
                );
            }
        }

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

/// Compute SHA-256 hash of bytes and return lowercase hex string.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex_encode(&result)
}

/// Encode bytes as lowercase hex string (avoids pulling in the `hex` crate).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse a checksums.toml file into a map of filename → SHA-256 hex hash.
///
/// Expected format:
/// ```toml
/// [checksums]
/// "elixir.toml" = "abc123..."
/// ```
fn parse_checksums(content: &str) -> Result<HashMap<String, String>> {
    #[derive(serde::Deserialize)]
    struct ChecksumsFile {
        checksums: HashMap<String, String>,
    }

    let parsed: ChecksumsFile = toml::from_str(content).context("invalid checksums.toml format")?;
    Ok(parsed.checksums)
}

/// Execute the `can init` command.
///
/// Clones community recipes to the local config directory.
/// Falls back to manual instructions if git is unavailable.
pub fn init(repo: Option<&str>, branch: Option<&str>, no_verify: bool) -> Result<i32> {
    let repo = repo.unwrap_or(DEFAULT_REPO);
    let branch = branch.unwrap_or(DEFAULT_BRANCH);
    let dest = recipe_install_dir()?;

    // When using a custom repo, default to no-verify since our embedded
    // checksums only cover the official repository.
    let verify = !no_verify && repo == DEFAULT_REPO;
    if !verify && !no_verify {
        tracing::info!(
            repo,
            "custom repository — checksum verification disabled (use official repo for verified recipes)"
        );
    }

    println!("Installing recipes to: {}", dest.display());
    println!();

    if !has_git() {
        print_manual_instructions(repo, branch, &dest);
        return Ok(1);
    }

    let installed = clone_and_install(&dest, repo, branch, verify)?;

    if installed.is_empty() {
        println!("No recipes found in the repository.");
        println!("Check that the repository contains a recipes/ directory with .toml files.");
    } else {
        println!("Installed {} recipes:", installed.len());
        for name in &installed {
            println!("  {name}");
        }
        println!();
        println!("Use `can recipe list` to see all available recipes.");
        println!("Use `can update` to refresh from the repository.");
    }

    Ok(0)
}

/// Execute the `can update` command.
///
/// Same as `init` — re-clones and overwrites all recipes.
pub fn update(repo: Option<&str>, branch: Option<&str>, no_verify: bool) -> Result<i32> {
    let repo = repo.unwrap_or(DEFAULT_REPO);
    let branch = branch.unwrap_or(DEFAULT_BRANCH);
    let dest = recipe_install_dir()?;

    let verify = !no_verify && repo == DEFAULT_REPO;
    if !verify && !no_verify {
        tracing::info!(repo, "custom repository — checksum verification disabled");
    }

    println!("Updating recipes in: {}", dest.display());
    println!();

    if !has_git() {
        print_manual_instructions(repo, branch, &dest);
        return Ok(1);
    }

    let installed = clone_and_install(&dest, repo, branch, verify)?;

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
        assert_eq!(url, "https://github.com/dergraf/canister.git");
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

    #[test]
    fn sha256_hex_known_value() {
        // SHA-256("hello\n") = known value
        let hash = sha256_hex(b"hello\n");
        assert_eq!(
            hash,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn parse_checksums_valid() {
        let toml = r#"
[checksums]
"foo.toml" = "abc123"
"bar.toml" = "def456"
"#;
        let cs = parse_checksums(toml).unwrap();
        assert_eq!(cs.len(), 2);
        assert_eq!(cs.get("foo.toml").unwrap(), "abc123");
        assert_eq!(cs.get("bar.toml").unwrap(), "def456");
    }

    #[test]
    fn parse_checksums_empty() {
        let toml = "[checksums]\n";
        let cs = parse_checksums(toml).unwrap();
        assert!(cs.is_empty());
    }

    #[test]
    fn parse_checksums_invalid() {
        let result = parse_checksums("not valid toml {{{}}}");
        assert!(result.is_err());
    }

    #[test]
    fn embedded_checksums_parse() {
        let cs = parse_checksums(EMBEDDED_CHECKSUMS).expect("embedded checksums should parse");
        assert!(
            cs.len() >= 10,
            "expected at least 10 checksums, got {}",
            cs.len()
        );
        // Verify a known recipe exists.
        assert!(
            cs.contains_key("elixir.toml"),
            "elixir.toml should have a checksum"
        );
    }

    #[test]
    fn embedded_checksums_match_actual_recipes() {
        // Verify that the embedded checksums match the actual recipe files
        // in the repository.
        let cs = parse_checksums(EMBEDDED_CHECKSUMS).unwrap();
        let recipes_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../recipes");

        for (name, expected_hash) in &cs {
            let recipe_path = recipes_dir.join(name);
            if recipe_path.exists() {
                let content = std::fs::read(&recipe_path)
                    .unwrap_or_else(|e| panic!("failed to read {name}: {e}"));
                let actual_hash = sha256_hex(&content);
                assert_eq!(
                    &actual_hash, expected_hash,
                    "checksum mismatch for {name} — run checksum regeneration"
                );
            }
        }
    }
}
