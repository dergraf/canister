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

    /// Path prefixes that trigger auto-detection of this recipe.
    ///
    /// When running a binary whose resolved path starts with one of these
    /// prefixes, this recipe is automatically composed into the recipe stack.
    /// Supports environment variable expansion (`$HOME`, `$USER`, etc.).
    ///
    /// Example: `["/nix/store"]` for the Nix package manager.
    #[serde(default)]
    pub match_prefix: Vec<String>,
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
}

impl RecipeFile {
    /// Load a recipe from a TOML file.
    ///
    /// R16: a recipe whose contents don't match a known-good SHA-256
    /// checksum is considered "untrusted." We still load and apply the
    /// recipe, but we **drop** its `[dlp.scopes]` entries so a malicious
    /// or stale third-party recipe can't silently widen credential trust.
    /// User-authored recipes are inherently untrusted under this scheme
    /// (their hashes are not in the embedded list); the workaround is to
    /// configure scopes in the project's own `canister.toml` manifest
    /// rather than in a downloaded recipe, or to pin the recipe via
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

    /// Drop `[dlp.scopes]` entries from this recipe unless the recipe's
    /// SHA-256 matches the embedded `recipes/checksums.toml` snapshot.
    /// Logs a warning per dropped detector at `warn` so the operator sees
    /// what was filtered.
    fn drop_untrusted_scopes(&mut self, filename: &str, content: &str) {
        if filename.is_empty() {
            return;
        }
        let Some(dlp) = self.network.dlp.as_mut() else {
            return;
        };
        if dlp.scopes.is_empty() {
            return;
        }
        if recipe_checksum_matches(filename, content) {
            return;
        }
        let detectors: Vec<String> = dlp.scopes.keys().cloned().collect();
        tracing::warn!(
            recipe = filename,
            detectors = ?detectors,
            "untrusted recipe: dropping [dlp.scopes] entries (recipe not pinned by checksum). \
             Move scope entries into your project's canister.toml or pin the recipe via `can pull`."
        );
        dlp.scopes.clear();
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

    /// Get the match_prefix patterns for auto-detection.
    pub fn match_prefixes(&self) -> &[String] {
        self.recipe
            .as_ref()
            .map(|m| m.match_prefix.as_slice())
            .unwrap_or(&[])
    }

    /// Get the match_prefix patterns with environment variables expanded.
    pub fn match_prefixes_expanded(&self) -> Vec<String> {
        self.match_prefixes()
            .iter()
            .map(|s| expand_env_vars(s))
            .collect()
    }
}

fn expand_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .map(|p| PathBuf::from(expand_env_vars(&p.to_string_lossy())))
        .collect()
}
