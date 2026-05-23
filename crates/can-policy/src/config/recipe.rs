//! Recipe-file loading, parsing, and resolution into a `SandboxConfig`.
//!
//! Recipes are the primary user-facing policy format. They compose a
//! complete sandbox policy by layering filesystem, network, process,
//! resource, and syscall rules on top of the single built-in baseline.
//!
//! The merge implementation lives in [`super::merge`]; this module only
//! provides the data definition + load/parse/resolve plumbing.

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::Deserialize;

use super::env::expand_env_vars;
use super::error::ConfigError;
use super::filesystem::FilesystemConfig;
use super::host::HostBlock;
use super::network::NetworkConfig;
use super::process::ProcessConfig;
use super::proxy::ProxyConfig;
use super::resources::ResourceConfig;
use super::sandbox::SandboxConfig;
use super::syscalls::SyscallConfig;
use super::trust::recipe_checksum_matches;

/// Metadata section for recipe files.
#[derive(Debug, Clone, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeMeta {
    /// Human-readable recipe name. Defaults to the filename stem when omitted.
    pub name: Option<String>,

    /// One-line description of what this recipe is for.
    #[serde(default)]
    pub description: Option<String>,

    /// Opaque version string (for humans, not parsed).
    #[serde(default)]
    pub version: Option<String>,

    /// Other recipe names that compose naturally with this one.
    ///
    /// Read by the interactive builder to surface companion recipes
    /// ("you picked elixir → consider hex, git, gh"). Not used at
    /// runtime — purely a UI/UX hint. Empty by default.
    #[serde(default)]
    pub suggests: Vec<String>,
}

/// A recipe file — the only entry point for parsing policy TOML files.
///
/// Files without a `[recipe]` section are valid — the field defaults
/// to `None` and the file is treated as a plain policy.
///
/// Recipes support composition via `merge()` — multiple recipes are
/// layered left-to-right with `Option` fields using last-wins-if-set
/// semantics and `Vec` fields using union semantics.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecipeFile {
    /// Recipe metadata (optional).
    #[serde(default)]
    pub recipe: Option<RecipeMeta>,

    /// Strict mode: fail hard instead of degrading gracefully.
    ///
    /// `None` means "not specified" — merge preserves earlier value.
    /// Uses OR semantics: any `Some(true)` wins. Resolved to `bool`
    /// via `into_sandbox_config()`.
    #[serde(default)]
    pub strict: Option<bool>,

    /// Filesystem access policy.
    #[serde(default)]
    pub filesystem: FilesystemConfig,

    /// Network access policy.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Process and environment restrictions.
    #[serde(default)]
    pub process: ProcessConfig,

    /// Resource limits (CPU, memory).
    #[serde(default)]
    pub resources: ResourceConfig,

    /// Syscall overrides on top of the default baseline.
    #[serde(default)]
    pub syscalls: SyscallConfig,

    /// L7 Proxy configuration.
    #[serde(default)]
    pub proxy: ProxyConfig,

    /// Per-destination egress contracts. See `host::HostBlock` and
    /// `docs/adr/0007-per-destination-egress-contracts.md`. Multiple
    /// blocks targeting the same domain are merged in `RecipeFile::merge`
    /// (vec union, max for `max_request_bytes`, last-Some-wins for
    /// `contract_mode`).
    #[serde(default, rename = "host")]
    pub hosts: Vec<HostBlock>,
}

impl RecipeFile {
    /// Load a recipe from a TOML file.
    ///
    /// A recipe whose contents don't match a known-good SHA-256
    /// checksum is considered "untrusted." We still load and apply
    /// the recipe, but we **drop** every `[[host]] allow_credentials`
    /// list so a malicious or stale third-party recipe can't
    /// silently widen credential trust. User-authored recipes are
    /// inherently untrusted under this scheme (their hashes aren't in
    /// the embedded list); the workaround is to configure credential
    /// scope in the project's own `canister.toml` manifest rather
    /// than in a downloaded recipe, or to pin the recipe via
    /// `can pull` against the canonical repo.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::ReadFile)?;
        let mut recipe = Self::parse(&content)?;
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        recipe.drop_untrusted_scopes(filename, &content);
        Ok(recipe)
    }

    /// Drop `[[host]] allow_credentials` entries from this recipe
    /// unless the recipe's SHA-256 matches the embedded
    /// `recipes/checksums.toml` snapshot. Logs a warning so the
    /// operator sees what was filtered.
    fn drop_untrusted_scopes(&mut self, filename: &str, content: &str) {
        if filename.is_empty() {
            return;
        }
        let any_credentials = self.hosts.iter().any(|h| !h.allow_credentials.is_empty());
        if !any_credentials {
            return;
        }
        if recipe_checksum_matches(filename, content) {
            return;
        }
        let dropped: Vec<(String, Vec<String>)> = self
            .hosts
            .iter()
            .filter(|h| !h.allow_credentials.is_empty())
            .map(|h| (h.domain.clone(), h.allow_credentials.clone()))
            .collect();
        tracing::warn!(
            recipe = filename,
            dropped = ?dropped,
            "untrusted recipe: dropping [[host]].allow_credentials entries (recipe not pinned by checksum). \
             Move credential-scope entries into your project's canister.toml or pin the recipe via `can pull`."
        );
        for h in &mut self.hosts {
            h.allow_credentials.clear();
        }
    }

    /// Parse a recipe from a TOML string.
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let recipe: Self = toml::from_str(content).map_err(ConfigError::Parse)?;
        recipe.syscalls.validate()?;
        Ok(recipe)
    }

    /// Resolve into a `SandboxConfig`.
    ///
    /// Fills in defaults for all `Option` fields:
    /// - `strict` → `false`
    /// - `network.egress` → `proxy-only`
    /// - `seccomp_mode` → `AllowList`
    ///
    /// Expands environment variables (`$HOME`, `$USER`, etc.) in:
    /// - `filesystem.allow` / `filesystem.allow_write` / `filesystem.deny`
    /// - `process.allow_execve`
    pub fn into_sandbox_config(self) -> Result<SandboxConfig, ConfigError> {
        Ok(SandboxConfig {
            strict: self.strict.unwrap_or(false),
            filesystem: FilesystemConfig {
                allow: expand_paths(self.filesystem.allow),
                allow_write: expand_paths(self.filesystem.allow_write),
                deny: expand_paths(self.filesystem.deny),
                mask: self.filesystem.mask,
            },
            network: self.network,
            process: ProcessConfig {
                max_pids: self.process.max_pids,
                allow_execve: expand_paths(self.process.allow_execve),
                env_passthrough: self.process.env_passthrough,
                env: self.process.env,
            },
            resources: self.resources,
            syscalls: self.syscalls,
            proxy: self.proxy,
            hosts: self.hosts,
        })
    }

    /// Get the display name for this recipe.
    pub fn display_name(&self, fallback: &str) -> String {
        self.recipe
            .as_ref()
            .and_then(|m| m.name.clone())
            .unwrap_or_else(|| fallback.to_string())
    }

    /// Get the description for this recipe.
    pub fn description(&self) -> &str {
        self.recipe
            .as_ref()
            .and_then(|m| m.description.as_deref())
            .unwrap_or("")
    }

    /// Get the names of recipes this one suggests as natural companions.
    pub fn suggests(&self) -> &[String] {
        self.recipe
            .as_ref()
            .map(|m| m.suggests.as_slice())
            .unwrap_or(&[])
    }
}

fn expand_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .map(|p| PathBuf::from(expand_env_vars(&p.to_string_lossy())))
        .collect()
}
