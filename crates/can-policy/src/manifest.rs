//! Project manifest (`canister.toml`) parsing and discovery.
//!
//! A manifest defines named sandboxes for a project, each composing
//! recipes with project-specific overrides. See ADR-0005 for the full
//! design.
//!
//! ## Example
//!
//! ```toml
//! [sandbox.dev]
//! description = "Neovim + Elixir development"
//! recipes = ["neovim", "elixir", "nix"]
//! command = "nvim"
//!
//! [sandbox.dev.filesystem]
//! allow_write = ["$HOME/.local/share/nvim"]
//!
//! [sandbox.test]
//! recipes = ["elixir", "nix"]
//! command = "mix test"
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config::{
    ConfigError, FilesystemConfig, NetworkConfig, ProcessConfig, RecipeFile, ResourceConfig,
    SyscallConfig,
};

/// Top-level project manifest parsed from `canister.toml`.
///
/// Contains a map of named sandbox definitions. The first-defined
/// sandbox is the default when `can up` is invoked without a name.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Named sandbox definitions.
    ///
    /// Each key is a sandbox name (e.g., "dev", "test", "ci").
    /// Order is preserved by the TOML parser for determining the default.
    pub sandbox: HashMap<String, SandboxDef>,
}

/// A named sandbox definition within the manifest.
///
/// Each sandbox declares which recipes to compose and the command to run,
/// with optional overrides that merge on top of the composed recipes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxDef {
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Recipe names to compose (resolved via the recipe search path).
    ///
    /// Merged left-to-right on top of `base.toml`.
    pub recipes: Vec<String>,

    /// Command to run inside the sandbox.
    ///
    /// May include arguments (e.g., `"mix test --cover"`).
    pub command: String,

    /// Override strict mode for this sandbox.
    #[serde(default)]
    pub strict: Option<bool>,

    /// Filesystem overrides merged on top of composed recipes.
    #[serde(default)]
    pub filesystem: FilesystemConfig,

    /// Network overrides merged on top of composed recipes.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Process overrides merged on top of composed recipes.
    #[serde(default)]
    pub process: ProcessConfig,

    /// Resource limit overrides.
    #[serde(default)]
    pub resources: ResourceConfig,

    /// Syscall overrides (allow_extra / deny_extra).
    #[serde(default)]
    pub syscalls: SyscallConfig,
}

/// The manifest filename searched for by `can up`.
pub const MANIFEST_FILENAME: &str = "canister.toml";

impl Manifest {
    /// Parse a manifest from a TOML string.
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let manifest: Self = toml::from_str(content).map_err(ConfigError::Parse)?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Load a manifest from a file.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::ReadFile)?;
        Self::parse(&content)
    }

    /// Validate the manifest after parsing.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.sandbox.is_empty() {
            return Err(ConfigError::Validation(
                "canister.toml must define at least one [sandbox.<name>] section".to_string(),
            ));
        }

        for (name, def) in &self.sandbox {
            if def.recipes.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "sandbox '{name}' must list at least one recipe in `recipes = [...]`"
                )));
            }
            if def.command.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "sandbox '{name}' must specify a `command`"
                )));
            }
            // Validate syscall config (no mixing absolute and relative).
            def.syscalls.validate()?;
        }

        Ok(())
    }

    /// Get a sandbox definition by name.
    pub fn get(&self, name: &str) -> Option<&SandboxDef> {
        self.sandbox.get(name)
    }

    /// Return all sandbox names (sorted for deterministic output).
    pub fn sandbox_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.sandbox.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    /// Convert a `SandboxDef` into a `RecipeFile` for merging.
    ///
    /// The overrides in a sandbox definition use the same structure as
    /// a recipe, so we can convert and use the existing merge machinery.
    pub fn sandbox_as_recipe(def: &SandboxDef) -> RecipeFile {
        RecipeFile {
            recipe: None,
            strict: def.strict,
            filesystem: def.filesystem.clone(),
            network: def.network.clone(),
            process: def.process.clone(),
            resources: def.resources.clone(),
            syscalls: def.syscalls.clone(),
        }
    }
}

impl SandboxDef {
    /// Split the command string into a command and arguments.
    ///
    /// Simple shell-like splitting on whitespace. Does NOT support
    /// quoting or escaping — commands with spaces in arguments should
    /// use explicit quoting at the shell level.
    pub fn command_parts(&self) -> Vec<String> {
        self.command
            .split_whitespace()
            .map(|s| s.to_string())
            .collect()
    }
}

/// Discover a `canister.toml` manifest by walking up from `start_dir`.
///
/// Checks the given directory and each parent directory until a
/// `canister.toml` file is found or the filesystem root is reached.
///
/// Returns the path to the manifest file, or `None` if not found.
pub fn discover_manifest(start_dir: &Path) -> Option<PathBuf> {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join(MANIFEST_FILENAME);
        if candidate.is_file() {
            tracing::debug!(path = %candidate.display(), "found canister.toml");
            return Some(candidate);
        }

        if !dir.pop() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_manifest() {
        let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"
"#;
        let manifest = Manifest::parse(toml).unwrap();
        assert_eq!(manifest.sandbox.len(), 1);
        let dev = manifest.get("dev").unwrap();
        assert_eq!(dev.recipes, vec!["elixir"]);
        assert_eq!(dev.command, "iex");
        assert!(dev.description.is_none());
        assert!(dev.strict.is_none());
    }

    #[test]
    fn parse_full_manifest() {
        let toml = r#"
[sandbox.dev]
description = "Neovim + Elixir development"
recipes = ["neovim", "elixir", "nix"]
command = "nvim"

[sandbox.dev.filesystem]
allow_write = ["$HOME/.local/share/nvim"]

[sandbox.dev.network]
allow_domains = ["api.myproject.dev"]

[sandbox.test]
description = "Mix test runner"
recipes = ["elixir", "nix"]
command = "mix test"

[sandbox.test.network]
deny_all = true

[sandbox.ci]
description = "CI — strict, no network"
recipes = ["elixir", "nix", "generic-strict"]
command = "mix test --cover"
strict = true

[sandbox.ci.resources]
memory_mb = 2048
cpu_percent = 100
"#;
        let manifest = Manifest::parse(toml).unwrap();
        assert_eq!(manifest.sandbox.len(), 3);

        let dev = manifest.get("dev").unwrap();
        assert_eq!(
            dev.description.as_deref(),
            Some("Neovim + Elixir development")
        );
        assert_eq!(dev.recipes, vec!["neovim", "elixir", "nix"]);
        assert_eq!(dev.command, "nvim");
        assert_eq!(dev.filesystem.allow_write.len(), 1);
        assert_eq!(dev.network.allow_domains, vec!["api.myproject.dev"]);

        let test = manifest.get("test").unwrap();
        assert_eq!(test.recipes, vec!["elixir", "nix"]);
        assert_eq!(test.command, "mix test");
        assert_eq!(test.network.deny_all, Some(true));

        let ci = manifest.get("ci").unwrap();
        assert_eq!(ci.recipes, vec!["elixir", "nix", "generic-strict"]);
        assert_eq!(ci.command, "mix test --cover");
        assert_eq!(ci.strict, Some(true));
        assert_eq!(ci.resources.memory_mb, Some(2048));
        assert_eq!(ci.resources.cpu_percent, Some(100));
    }

    #[test]
    fn parse_manifest_with_syscall_overrides() {
        let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"

[sandbox.dev.syscalls]
allow_extra = ["ptrace"]
deny_extra = ["personality"]
"#;
        let manifest = Manifest::parse(toml).unwrap();
        let dev = manifest.get("dev").unwrap();
        assert_eq!(dev.syscalls.allow_extra, vec!["ptrace"]);
        assert_eq!(dev.syscalls.deny_extra, vec!["personality"]);
    }

    #[test]
    fn reject_empty_manifest() {
        // No [sandbox] section at all.
        let toml = "";
        let result = Manifest::parse(toml);
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_sandbox_section() {
        let toml = "[sandbox]\n";
        let result = Manifest::parse(toml);
        assert!(result.is_err(), "empty [sandbox] should be rejected");
    }

    #[test]
    fn reject_sandbox_without_recipes() {
        let toml = r#"
[sandbox.dev]
command = "nvim"
"#;
        let result = Manifest::parse(toml);
        assert!(
            result.is_err(),
            "sandbox without recipes should be rejected"
        );
    }

    #[test]
    fn reject_sandbox_with_empty_recipes() {
        let toml = r#"
[sandbox.dev]
recipes = []
command = "nvim"
"#;
        let result = Manifest::parse(toml);
        assert!(
            result.is_err(),
            "sandbox with empty recipes should be rejected"
        );
    }

    #[test]
    fn reject_sandbox_without_command() {
        let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
"#;
        let result = Manifest::parse(toml);
        assert!(
            result.is_err(),
            "sandbox without command should be rejected"
        );
    }

    #[test]
    fn reject_sandbox_with_empty_command() {
        let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = ""
"#;
        let result = Manifest::parse(toml);
        assert!(
            result.is_err(),
            "sandbox with empty command should be rejected"
        );
    }

    #[test]
    fn reject_unknown_fields() {
        let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"
bogus = "nope"
"#;
        let result = Manifest::parse(toml);
        assert!(result.is_err(), "unknown fields should be rejected");
    }

    #[test]
    fn reject_unknown_top_level_fields() {
        let toml = r#"
extra_stuff = true

[sandbox.dev]
recipes = ["elixir"]
command = "iex"
"#;
        let result = Manifest::parse(toml);
        assert!(
            result.is_err(),
            "unknown top-level fields should be rejected"
        );
    }

    #[test]
    fn sandbox_names_sorted() {
        let toml = r#"
[sandbox.zebra]
recipes = ["elixir"]
command = "z"

[sandbox.alpha]
recipes = ["elixir"]
command = "a"

[sandbox.middle]
recipes = ["elixir"]
command = "m"
"#;
        let manifest = Manifest::parse(toml).unwrap();
        assert_eq!(manifest.sandbox_names(), vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn command_parts_splits_whitespace() {
        let toml = r#"
[sandbox.test]
recipes = ["elixir"]
command = "mix test --cover --force"
"#;
        let manifest = Manifest::parse(toml).unwrap();
        let test = manifest.get("test").unwrap();
        assert_eq!(
            test.command_parts(),
            vec!["mix", "test", "--cover", "--force"]
        );
    }

    #[test]
    fn sandbox_as_recipe_converts() {
        let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"
strict = true

[sandbox.dev.filesystem]
allow_write = ["/tmp/state"]

[sandbox.dev.network]
allow_domains = ["hex.pm"]

[sandbox.dev.syscalls]
allow_extra = ["ptrace"]
"#;
        let manifest = Manifest::parse(toml).unwrap();
        let dev = manifest.get("dev").unwrap();
        let recipe = Manifest::sandbox_as_recipe(dev);

        assert_eq!(recipe.strict, Some(true));
        assert_eq!(recipe.filesystem.allow_write.len(), 1);
        assert_eq!(recipe.network.allow_domains, vec!["hex.pm"]);
        assert_eq!(recipe.syscalls.allow_extra, vec!["ptrace"]);
    }

    #[test]
    fn discover_manifest_finds_in_current_dir() {
        // Create a temp directory with a canister.toml.
        let tmp = std::env::temp_dir().join("canister-test-discover");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let manifest_path = tmp.join("canister.toml");
        std::fs::write(
            &manifest_path,
            "[sandbox.dev]\nrecipes = [\"base\"]\ncommand = \"sh\"\n",
        )
        .unwrap();

        let result = discover_manifest(&tmp);
        assert_eq!(result, Some(manifest_path));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn discover_manifest_walks_up() {
        // Create parent/child structure, manifest only in parent.
        let tmp = std::env::temp_dir().join("canister-test-discover-walk");
        let child = tmp.join("subdir").join("deep");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&child).unwrap();

        let manifest_path = tmp.join("canister.toml");
        std::fs::write(
            &manifest_path,
            "[sandbox.dev]\nrecipes = [\"base\"]\ncommand = \"sh\"\n",
        )
        .unwrap();

        let result = discover_manifest(&child);
        assert_eq!(result, Some(manifest_path));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn discover_manifest_returns_none_when_not_found() {
        // Use a temp dir with no manifest anywhere.
        let tmp = std::env::temp_dir().join("canister-test-discover-none");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let result = discover_manifest(&tmp);
        assert!(result.is_none());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn reject_mixed_syscall_modes_in_sandbox() {
        let toml = r#"
[sandbox.dev]
recipes = ["elixir"]
command = "iex"

[sandbox.dev.syscalls]
allow = ["read", "write"]
allow_extra = ["ptrace"]
"#;
        let result = Manifest::parse(toml);
        assert!(result.is_err(), "mixing allow and allow_extra should fail");
    }
}
