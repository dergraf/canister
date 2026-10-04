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

use std::collections::{BTreeMap, HashMap};
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
    /// Recipe repositories by name (ADR-0026). A sandbox names a recipe
    /// from one as `<source>/<recipe>`; `canister.lock` pins each to a
    /// revision.
    #[serde(default)]
    pub sources: BTreeMap<String, SourceSpec>,

    /// Named sandbox definitions.
    ///
    /// Each key is a sandbox name (e.g., "dev", "test", "ci").
    /// Order is preserved by the TOML parser for determining the default.
    pub sandbox: HashMap<String, SandboxDef>,
}

/// Where a source's recipes come from: a git repository pinned by a tag
/// or a revision, or a directory relative to `canister.toml`.
///
/// ```toml
/// [sources]
/// team = { git = "https://git.example/team/canister-recipes", tag = "2026.1" }
/// local = { path = "recipes" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSpec {
    #[serde(default)]
    pub git: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub rev: Option<String>,
    #[serde(default)]
    pub path: Option<PathBuf>,
}

impl SourceSpec {
    fn validate(&self, name: &str) -> Result<(), ConfigError> {
        let invalid = |why: &str| Err(ConfigError::Validation(format!("source '{name}': {why}")));
        match (&self.git, &self.path) {
            (Some(_), Some(_)) => invalid("either `git` or `path`, not both"),
            (None, None) => invalid("needs `git` (with a `tag` or `rev`) or `path`"),
            (Some(_), None) if self.tag.is_none() && self.rev.is_none() => invalid(
                "a git source needs a `tag` or a `rev`, so a sandbox is built from a known version",
            ),
            (None, Some(_)) if self.tag.is_some() || self.rev.is_some() => {
                invalid("`tag` and `rev` only apply to a git source")
            }
            _ if name.is_empty() || name.contains('/') => {
                invalid("a source name is one word, without `/`")
            }
            _ => Ok(()),
        }
    }
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
    /// Merged left-to-right on top of `base.toml`. Every sandbox must
    /// declare at least one recipe. Recipes live in category subdirectories
    /// under the recipe search path (`languages/`, `package-managers/`,
    /// `vcs/`, …); names are looked up recursively.
    #[serde(default)]
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

    /// L7 Proxy configuration overrides.
    #[serde(default)]
    pub proxy: ProxyConfig,

    /// Per-destination egress contracts ([[host]]). Merged additively
    /// with whatever the composed recipes declare — extending a
    /// shipped contract is the same shape as adding a new one.
    #[serde(default, rename = "host")]
    pub hosts: Vec<super::config::HostBlock>,

    /// Isolation-weakening overrides. The manifest is a trusted,
    /// project-owned file, so `[sandbox.<name>.unsafe]` is the right place
    /// for a project to opt into host loopback, extra IPs, etc.
    #[serde(default, rename = "unsafe")]
    pub unsafe_block: super::config::UnsafeConfig,
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
        for (name, source) in &self.sources {
            source.validate(name)?;
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

    /// Split a recipe name into a declared source and the recipe within
    /// it: `team/internal-api` when `team` is a source; `None` for a
    /// library recipe or a path.
    pub fn source_recipe<'a>(&self, recipe: &'a str) -> Option<(&str, &'a str)> {
        let (source, rest) = recipe.split_once('/')?;
        let (name, _spec) = self.sources.get_key_value(source)?;
        (!rest.is_empty()).then_some((name.as_str(), rest))
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
        if self.recipes.is_empty() {
            return Err(ConfigError::Validation(format!(
                "sandbox '{name}' must list at least one entry in `recipes = [...]`"
            )));
        }
        if self.command.is_empty() {
            return Err(ConfigError::Validation(format!(
                "sandbox '{name}' must specify a `command`"
            )));
        }
        // Validate syscall config (no mixing absolute and relative).
        self.syscalls.validate()?;
        for host in &self.hosts {
            host.validate()
                .map_err(|e| ConfigError::Validation(format!("sandbox '{name}': {e}")))?;
        }
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
            hosts: def.hosts.clone(),
            unsafe_block: def.unsafe_block.clone(),
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
