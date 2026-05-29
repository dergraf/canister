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
use super::network::{EgressMode, NetworkConfig};
use super::process::{ExecPolicy, ProcessConfig};
use super::proxy::ProxyConfig;
use super::resources::ResourceConfig;
use super::sandbox::SandboxConfig;
use super::syscalls::{SeccompMode, SyscallConfig};
use super::trust::recipe_checksum_matches;
use super::unsafe_config::UnsafeConfig;

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

    /// Isolation-weakening settings. Quarantined here so a recipe with no
    /// `[unsafe]` block provably cannot lower the baseline. Folded into the
    /// runtime network/syscall config at resolve time.
    #[serde(default, rename = "unsafe")]
    pub unsafe_block: UnsafeConfig,
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

    /// Drop credential-trust entries from this recipe unless its SHA-256
    /// matches the embedded `recipes/checksums.toml` snapshot. Covers both
    /// `[[host]] allow_credentials` and `[network.dlp] fake_secrets`: each
    /// routes a real credential to an authorized host, so an unpinned
    /// third-party recipe must not be able to declare either. Logs a
    /// warning so the operator sees what was filtered.
    fn drop_untrusted_scopes(&mut self, filename: &str, content: &str) {
        if filename.is_empty() {
            return;
        }
        let any_credentials = self.hosts.iter().any(|h| !h.allow_credentials.is_empty());
        let any_fakes = self
            .network
            .dlp
            .as_ref()
            .is_some_and(|d| !d.fake_secrets.is_empty());
        if !any_credentials && !any_fakes {
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
        let dropped_fakes: Vec<String> = self
            .network
            .dlp
            .as_ref()
            .map(|d| d.fake_secrets.iter().map(|f| f.env.clone()).collect())
            .unwrap_or_default();
        tracing::warn!(
            recipe = filename,
            dropped = ?dropped,
            dropped_fake_secrets = ?dropped_fakes,
            "untrusted recipe: dropping [[host]].allow_credentials and [network.dlp].fake_secrets entries (recipe not pinned by checksum). \
             Move credential-scope entries into your project's canister.toml or pin the recipe via `can pull`."
        );
        for h in &mut self.hosts {
            h.allow_credentials.clear();
        }
        if let Some(dlp) = self.network.dlp.as_mut() {
            dlp.fake_secrets.clear();
        }
    }

    /// Parse a recipe from a TOML string.
    pub fn parse(content: &str) -> Result<Self, ConfigError> {
        let recipe: Self = toml::from_str(content).map_err(ConfigError::Parse)?;
        recipe.syscalls.validate()?;
        recipe.validate()?;
        Ok(recipe)
    }

    /// Recipe-level validation that spans sections.
    fn validate(&self) -> Result<(), ConfigError> {
        // `egress = "direct"` deserializes (the runtime needs the variant)
        // but is not a thing a recipe may *ask* for — it disables DLP and
        // contract gates. Point the author at the quarantined knob.
        if self.network.egress == Some(EgressMode::Direct) {
            return Err(ConfigError::Validation(
                "[network] egress = \"direct\" is not allowed; unfiltered egress disables DLP \
                 and contract gates — declare [unsafe] unfiltered_egress = true instead."
                    .to_string(),
            ));
        }

        // Contradiction: credential scope / DLP / fakes do nothing without
        // the proxy. Reject rather than silently no-op.
        if self.unsafe_block.unfiltered_egress {
            let dlp_configured = self
                .network
                .dlp
                .as_ref()
                .is_some_and(|d| d.is_enabled() || !d.fake_secrets.is_empty());
            let creds = self.hosts.iter().any(|h| !h.allow_credentials.is_empty());
            if dlp_configured || creds {
                return Err(ConfigError::Validation(
                    "[unsafe] unfiltered_egress bypasses the proxy, so [network.dlp], \
                     fake_secrets, and [[host]] allow_credentials would have no effect. \
                     Remove unfiltered_egress or drop those settings."
                        .to_string(),
                ));
            }

            // Contradiction: an egress allow-list (reachable_ips or [[host]]
            // blocks) declares "only these destinations," but unfiltered
            // egress enforces no destination policy at all. With the
            // USER_NOTIF connect() supervisor removed, egress is enforced by
            // the network topology: proxy mode gives the worker no uplink,
            // direct mode gives it a full one. There is no longer any layer
            // that could honor an allow-list under unfiltered egress, so
            // reject the combination rather than ship one silently
            // unenforced.
            if !self.unsafe_block.reachable_ips.is_empty() || !self.hosts.is_empty() {
                return Err(ConfigError::Validation(
                    "[unsafe] unfiltered_egress is incompatible with an egress allow-list \
                     (reachable_ips or [[host]] blocks): unfiltered egress enforces no \
                     destination policy, so the allow-list could not be enforced \
                     structurally. Use egress = \"proxy\" to enforce the allow-list, or \
                     drop the allow-list."
                        .to_string(),
                ));
            }
        }
        Ok(())
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
                read: expand_paths(self.filesystem.read),
                write: expand_paths(self.filesystem.write),
                deny: expand_paths(self.filesystem.deny),
                mask: self.filesystem.mask,
            },
            // Fold the [unsafe] block back into the runtime network config:
            // these knobs live in [unsafe] for authoring visibility but the
            // runtime reads them from their original locations.
            network: {
                let mut network = self.network;
                network.allow_ips = self.unsafe_block.reachable_ips;
                network.ports = self.unsafe_block.expose_ports;
                network.allow_host_loopback = self.unsafe_block.host_loopback;
                if self.unsafe_block.unfiltered_egress {
                    network.egress = Some(EgressMode::Direct);
                }
                network
            },
            process: ProcessConfig {
                max_pids: self.process.max_pids,
                exec: Some(expand_exec(self.process.exec())),
                env_passthrough: self.process.env_passthrough,
                env: self.process.env,
            },
            resources: self.resources,
            syscalls: {
                let mut syscalls = self.syscalls;
                if self.unsafe_block.seccomp_default_allow {
                    syscalls.seccomp_mode = Some(SeccompMode::DenyList);
                }
                // [unsafe] extra_syscalls are the high-risk allow-list
                // additions; merge them into the resolved allow_extra so
                // seccomp applies them uniformly.
                syscalls
                    .allow_extra
                    .extend(self.unsafe_block.extra_syscalls);
                syscalls
            },
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

/// Env-expand the paths inside an explicit-allow exec policy; modes pass
/// through unchanged.
fn expand_exec(exec: ExecPolicy) -> ExecPolicy {
    match exec {
        ExecPolicy::Allow(paths) => ExecPolicy::Allow(expand_paths(paths)),
        mode @ ExecPolicy::Mode(_) => mode,
    }
}
