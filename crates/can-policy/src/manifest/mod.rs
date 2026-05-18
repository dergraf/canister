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

use schemars::JsonSchema;
use serde::Deserialize;

use crate::config::{
    ConfigError, FilesystemConfig, NetworkConfig, ProcessConfig, ProxyConfig, RecipeFile,
    ResourceConfig, SyscallConfig,
};

/// Top-level project manifest parsed from `canister.toml`.
///
/// Contains a map of named sandbox definitions. The first-defined
/// sandbox is the default when `can up` is invoked without a name.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SandboxDef {
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Recipe names to compose (resolved via the recipe search path).
    ///
    /// Merged left-to-right on top of `base.toml`. May be empty when
    /// `tools = [...]` is set instead — every sandbox must declare at
    /// least one of `recipes` or `tools`.
    #[serde(default)]
    pub recipes: Vec<String>,

    /// Curated tool shortcuts. Each name `npm` expands to recipe
    /// `tool:npm`, looked up in the `tools/` sub-namespace of the
    /// recipe search path. Tool recipes are small per-tool bundles
    /// (filesystem paths + env passthrough + known egress domains)
    /// shipped via the community registry. Composed BEFORE `recipes`
    /// so explicit recipes can override tool defaults if needed.
    #[serde(default)]
    pub tools: Vec<String>,

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

    /// L7 Proxy configuration overrides.
    #[serde(default)]
    pub proxy: ProxyConfig,
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

    /// Validate the manifest after parsing. Per-sandbox checks live on
    /// `SandboxDef::validate` so a `SandboxDef` constructed by other
    /// means can also be validated in isolation.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.sandbox.is_empty() {
            return Err(ConfigError::Validation(
                "canister.toml must define at least one [sandbox.<name>] section".to_string(),
            ));
        }
        for (name, def) in &self.sandbox {
            def.validate(name)?;
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

    /// Validate this sandbox definition. `name` is included in error
    /// messages so the caller can identify which sandbox failed when
    /// iterating a `Manifest`.
    pub fn validate(&self, name: &str) -> Result<(), ConfigError> {
        if self.recipes.is_empty() && self.tools.is_empty() {
            return Err(ConfigError::Validation(format!(
                "sandbox '{name}' must list at least one entry in \
                 `recipes = [...]` or `tools = [...]`"
            )));
        }
        if self.command.is_empty() {
            return Err(ConfigError::Validation(format!(
                "sandbox '{name}' must specify a `command`"
            )));
        }
        // Validate syscall config (no mixing absolute and relative).
        self.syscalls.validate()?;
        Ok(())
    }
}

/// Convert a `SandboxDef` into a `RecipeFile` for merging.
///
/// The overrides in a sandbox definition use the same structure as a
/// recipe, so we can convert and feed the existing merge machinery.
/// `From<&SandboxDef>` matches Rust convention better than a free
/// associated function; the conversion is otherwise unchanged.
impl From<&SandboxDef> for RecipeFile {
    fn from(def: &SandboxDef) -> Self {
        RecipeFile {
            recipe: None,
            strict: def.strict,
            filesystem: def.filesystem.clone(),
            network: def.network.clone(),
            process: def.process.clone(),
            resources: def.resources.clone(),
            syscalls: def.syscalls.clone(),
            proxy: def.proxy.clone(),
        }
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
mod tests;
