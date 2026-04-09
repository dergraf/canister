use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level sandbox configuration.
///
/// This is the resolved, validated form used by the sandbox runtime.
/// All `Option` fields are guaranteed to be `Some` after resolution
/// via `RecipeFile::into_sandbox_config()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Strict mode: fail hard instead of degrading gracefully.
    ///
    /// When true, any setup failure (filesystem isolation, seccomp, cgroups)
    /// is a fatal error instead of a warning. Seccomp uses KILL_PROCESS
    /// instead of ERRNO. Intended for CI / production use.
    #[serde(default)]
    pub strict: bool,

    /// Allow degraded mode: permit sandbox to continue when isolation
    /// features are unavailable.
    ///
    /// By default (`false`), canister fails hard when isolation cannot be
    /// established (e.g., filesystem overlay fails). Set to `true` to
    /// allow running with reduced isolation.
    ///
    /// Mutually exclusive with `strict`.
    #[serde(default)]
    pub allow_degraded: bool,

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

    /// Seccomp syscall overrides and enforcement mode.
    #[serde(default)]
    pub syscalls: SyscallConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    /// Paths the sandboxed process is allowed to access.
    #[serde(default)]
    pub allow: Vec<PathBuf>,

    /// Paths explicitly denied (checked before allow).
    #[serde(default)]
    pub deny: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Whitelisted domain names (resolved via internal DNS proxy).
    #[serde(default)]
    pub allow_domains: Vec<String>,

    /// Whitelisted IP addresses or CIDR ranges.
    #[serde(default)]
    pub allow_ips: Vec<String>,

    /// If true, deny all network access except explicitly allowed.
    /// Defaults to true (secure by default) when resolved.
    ///
    /// `None` in a recipe means "not specified" — the merge preserves
    /// the earlier value. `into_sandbox_config()` resolves `None` to `true`.
    #[serde(default)]
    pub deny_all: Option<bool>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            allow_domains: Vec::new(),
            allow_ips: Vec::new(),
            deny_all: None,
        }
    }
}

impl NetworkConfig {
    /// Return the effective `deny_all` value (defaults to `true`).
    pub fn deny_all(&self) -> bool {
        self.deny_all.unwrap_or(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProcessConfig {
    /// Maximum number of child PIDs allowed.
    pub max_pids: Option<u32>,

    /// Paths to executables the sandboxed process may exec.
    #[serde(default)]
    pub allow_execve: Vec<PathBuf>,

    /// Environment variables to pass through from the host.
    /// All others are stripped.
    #[serde(default)]
    pub env_passthrough: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    /// Memory limit in megabytes.
    pub memory_mb: Option<u64>,

    /// CPU limit as a percentage (e.g., 50 = 50% of one core).
    pub cpu_percent: Option<u32>,
}

/// Seccomp enforcement mode.
///
/// Controls how the seccomp BPF filter is constructed:
/// - **AllowList** (default): default action is DENY. Only explicitly listed
///   syscalls are allowed. This is the secure choice for production/CI.
/// - **DenyList**: default action is ALLOW. Only explicitly listed syscalls
///   are blocked. More permissive, useful when compatibility is paramount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeccompMode {
    /// Default deny — only allow-listed syscalls are permitted.
    #[default]
    AllowList,
    /// Default allow — only deny-listed syscalls are blocked.
    DenyList,
}

impl fmt::Display for SeccompMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowList => write!(f, "allow-list"),
            Self::DenyList => write!(f, "deny-list"),
        }
    }
}

/// Syscall customization.
///
/// Two mutually exclusive modes:
///
/// **Baseline mode** (`allow` + `deny`): absolute syscall lists that define
/// the entire policy. Only used by `default.toml` — the canonical baseline.
///
/// **Override mode** (`allow_extra` + `deny_extra`): relative adjustments
/// layered on top of the baseline. Used by all regular recipes.
///
/// A recipe MUST NOT mix absolute and relative fields. If both are present,
/// parsing succeeds but `validate()` returns an error.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SyscallConfig {
    /// Seccomp enforcement mode: "allow-list" (default) or "deny-list".
    ///
    /// `None` means "not specified" — merge preserves earlier value,
    /// `into_sandbox_config()` resolves to `AllowList`.
    #[serde(default)]
    pub seccomp_mode: Option<SeccompMode>,

    /// Enable the SECCOMP_RET_USER_NOTIF supervisor for argument-level
    /// syscall filtering (connect, clone, socket, execve).
    ///
    /// Requires Linux 5.9+. When `None`, auto-detected based on kernel
    /// version. Set to `false` to explicitly disable.
    #[serde(default)]
    pub notifier: Option<bool>,

    // --- Absolute fields (baseline only) ---
    /// Absolute allow list — the complete set of permitted syscalls.
    /// Only valid in `default.toml`. Mutually exclusive with `allow_extra`.
    #[serde(default)]
    pub allow: Vec<String>,

    /// Absolute deny list — syscalls always blocked.
    /// Only valid in `default.toml`. Mutually exclusive with `deny_extra`.
    #[serde(default)]
    pub deny: Vec<String>,

    // --- Relative fields (regular recipes) ---
    /// Syscalls to add to the allow list (on top of the default baseline).
    ///
    /// Example: `["ptrace", "io_uring_setup", "io_uring_enter", "io_uring_register"]`
    #[serde(default)]
    pub allow_extra: Vec<String>,

    /// Syscalls to add to the deny list (also removed from allow list).
    ///
    /// Example: `["personality"]` to block multilib switching.
    #[serde(default)]
    pub deny_extra: Vec<String>,
}

impl SyscallConfig {
    /// Return the effective seccomp mode (defaults to `AllowList`).
    pub fn seccomp_mode(&self) -> SeccompMode {
        self.seccomp_mode.unwrap_or_default()
    }

    /// Return whether the notifier should be enabled.
    ///
    /// `None` means auto-detect (caller checks kernel version).
    /// `Some(true)` forces on, `Some(false)` forces off.
    pub fn notifier_enabled(&self) -> Option<bool> {
        self.notifier
    }

    /// Returns true if this config uses absolute allow/deny fields (baseline mode).
    pub fn is_baseline(&self) -> bool {
        !self.allow.is_empty() || !self.deny.is_empty()
    }

    /// Returns true if this config uses relative allow_extra/deny_extra fields (override mode).
    pub fn is_override(&self) -> bool {
        !self.allow_extra.is_empty() || !self.deny_extra.is_empty()
    }

    /// Validate that absolute and relative fields are not mixed.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.is_baseline() && self.is_override() {
            return Err(ConfigError::Validation(
                "[syscalls] cannot mix absolute (allow/deny) and relative (allow_extra/deny_extra) fields. \
                 Use allow/deny only in default.toml; use allow_extra/deny_extra in regular recipes."
                    .to_string(),
            ));
        }
        Ok(())
    }
}

impl SandboxConfig {
    /// Return a default config with sensible defaults (deny-all).
    pub fn default_deny() -> Self {
        Self {
            strict: false,
            allow_degraded: false,
            filesystem: FilesystemConfig::default(),
            network: NetworkConfig::default(),
            process: ProcessConfig::default(),
            resources: ResourceConfig::default(),
            syscalls: SyscallConfig::default(),
        }
    }
}

/// Errors from loading or parsing configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadFile(std::io::Error),

    #[error("invalid config format: {0}")]
    Parse(toml::de::Error),

    #[error("invalid config: {0}")]
    Validation(String),
}

// ---------------------------------------------------------------------------
// Recipe support
// ---------------------------------------------------------------------------

/// Metadata section for recipe files.
///
/// Recipes are the primary user-facing policy format. They compose a
/// complete sandbox policy by layering filesystem, network, process,
/// resource, and syscall rules on top of the single built-in baseline.
#[derive(Debug, Clone, Deserialize, Default)]
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
#[derive(Debug, Clone, Deserialize)]
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

    /// Allow degraded mode: permit sandbox to continue when isolation
    /// features are unavailable (e.g., AppArmor blocks mount operations).
    ///
    /// By default, canister fails hard when isolation cannot be established.
    /// Set this to `true` to allow running with reduced isolation (e.g.,
    /// host filesystem fallback when overlay setup fails).
    ///
    /// `None` means "not specified" — merge preserves earlier value.
    /// Uses OR semantics: any `Some(true)` wins. Resolved to `false`
    /// via `into_sandbox_config()`.
    #[serde(default)]
    pub allow_degraded: Option<bool>,

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
}

impl RecipeFile {
    /// Load a recipe from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::ReadFile)?;
        Self::from_str(&content)
    }

    /// Parse a recipe from a TOML string.
    pub fn from_str(content: &str) -> Result<Self, ConfigError> {
        let recipe: Self = toml::from_str(content).map_err(ConfigError::Parse)?;
        recipe.syscalls.validate()?;
        Ok(recipe)
    }

    /// Resolve into a `SandboxConfig`.
    ///
    /// Fills in defaults for all `Option` fields:
    /// - `strict` → `false`
    /// - `allow_degraded` → `false`
    /// - `deny_all` → `true`
    /// - `seccomp_mode` → `AllowList`
    ///
    /// Expands environment variables (`$HOME`, `$USER`, etc.) in:
    /// - `filesystem.allow` / `filesystem.deny`
    /// - `process.allow_execve`
    pub fn into_sandbox_config(self) -> Result<SandboxConfig, ConfigError> {
        Ok(SandboxConfig {
            strict: self.strict.unwrap_or(false),
            allow_degraded: self.allow_degraded.unwrap_or(false),
            filesystem: FilesystemConfig {
                allow: self
                    .filesystem
                    .allow
                    .into_iter()
                    .map(|p| PathBuf::from(expand_env_vars(&p.to_string_lossy())))
                    .collect(),
                deny: self
                    .filesystem
                    .deny
                    .into_iter()
                    .map(|p| PathBuf::from(expand_env_vars(&p.to_string_lossy())))
                    .collect(),
            },
            network: self.network,
            process: ProcessConfig {
                max_pids: self.process.max_pids,
                allow_execve: self
                    .process
                    .allow_execve
                    .into_iter()
                    .map(|p| PathBuf::from(expand_env_vars(&p.to_string_lossy())))
                    .collect(),
                env_passthrough: self.process.env_passthrough,
            },
            resources: self.resources,
            syscalls: self.syscalls,
        })
    }

    /// Merge another recipe on top of this one (layered composition).
    ///
    /// **Merge rules:**
    /// - `Vec` fields: union (deduplicated, preserving order)
    /// - `strict`: OR — any `Some(true)` wins
    /// - `Option<T>` scalars: last `Some(x)` wins; `None` preserves base
    /// - `RecipeMeta`: overlay wins if present
    pub fn merge(self, overlay: RecipeFile) -> RecipeFile {
        RecipeFile {
            // Metadata: overlay wins if present.
            recipe: overlay.recipe.or(self.recipe),

            // Strict: OR — any Some(true) wins.
            strict: match (self.strict, overlay.strict) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (_, s @ Some(_)) => s,
                (s, None) => s,
            },

            // Allow degraded: OR — any Some(true) wins.
            allow_degraded: match (self.allow_degraded, overlay.allow_degraded) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (_, s @ Some(_)) => s,
                (s, None) => s,
            },

            // Filesystem: union of paths.
            filesystem: FilesystemConfig {
                allow: union_vecs(self.filesystem.allow, overlay.filesystem.allow),
                deny: union_vecs(self.filesystem.deny, overlay.filesystem.deny),
            },

            // Network: union of lists, deny_all is last-Some-wins.
            network: NetworkConfig {
                allow_domains: union_vecs(
                    self.network.allow_domains,
                    overlay.network.allow_domains,
                ),
                allow_ips: union_vecs(self.network.allow_ips, overlay.network.allow_ips),
                deny_all: overlay.network.deny_all.or(self.network.deny_all),
            },

            // Process: union of lists, max_pids is last-Some-wins.
            process: ProcessConfig {
                max_pids: overlay.process.max_pids.or(self.process.max_pids),
                allow_execve: union_vecs(self.process.allow_execve, overlay.process.allow_execve),
                env_passthrough: union_vecs(
                    self.process.env_passthrough,
                    overlay.process.env_passthrough,
                ),
            },

            // Resources: last-Some-wins.
            resources: ResourceConfig {
                memory_mb: overlay.resources.memory_mb.or(self.resources.memory_mb),
                cpu_percent: overlay.resources.cpu_percent.or(self.resources.cpu_percent),
            },

            // Syscalls: seccomp_mode is last-Some-wins, notifier is last-Some-wins, extras are unioned.
            // Absolute fields (allow/deny) are also unioned — this supports
            // merging a baseline on top of another, though in practice only
            // one recipe should use absolute fields.
            syscalls: SyscallConfig {
                seccomp_mode: overlay.syscalls.seccomp_mode.or(self.syscalls.seccomp_mode),
                notifier: overlay.syscalls.notifier.or(self.syscalls.notifier),
                allow: union_vecs(self.syscalls.allow, overlay.syscalls.allow),
                deny: union_vecs(self.syscalls.deny, overlay.syscalls.deny),
                allow_extra: union_vecs(self.syscalls.allow_extra, overlay.syscalls.allow_extra),
                deny_extra: union_vecs(self.syscalls.deny_extra, overlay.syscalls.deny_extra),
            },
        }
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

/// Expand environment variables in a string.
///
/// Supports two forms:
/// - `$NAME` — bare variable (terminated by non-alphanumeric, non-underscore)
/// - `${NAME}` — braced variable
///
/// Unknown or unset variables are replaced with an empty string.
/// Literal `$$` is escaped to a single `$`.
///
/// This is intentionally simple — no default values, no nested expansion.
/// Used for recipe paths like `$HOME/.cargo/bin`.
pub fn expand_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '$' {
            result.push(ch);
            continue;
        }

        // $$ → literal $
        if chars.peek() == Some(&'$') {
            chars.next();
            result.push('$');
            continue;
        }

        // ${NAME} — braced form
        if chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut name = String::new();
            for c in chars.by_ref() {
                if c == '}' {
                    break;
                }
                name.push(c);
            }
            if let Ok(val) = std::env::var(&name) {
                result.push_str(&val);
            }
            continue;
        }

        // $NAME — bare form (alphanumeric + underscore)
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                name.push(c);
                chars.next();
            } else {
                break;
            }
        }

        if name.is_empty() {
            // Lone $ at end of string or before non-identifier char
            result.push('$');
        } else if let Ok(val) = std::env::var(&name) {
            result.push_str(&val);
        }
        // Unset variables expand to empty string (no output).
    }

    result
}

/// Merge two `Vec<T>` by appending, deduplicating (preserving first occurrence order).
fn union_vecs<T: Clone + Eq + std::hash::Hash>(base: Vec<T>, overlay: Vec<T>) -> Vec<T> {
    let mut seen = HashSet::with_capacity(base.len() + overlay.len());
    let mut result = Vec::with_capacity(base.len() + overlay.len());
    for item in base.into_iter().chain(overlay) {
        if seen.insert(item.clone()) {
            result.push(item);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[filesystem]
allow = ["/usr/lib", "/tmp/workspace"]

[network]
allow_domains = ["pypi.org"]
"#;
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.filesystem.allow.len(), 2);
        assert_eq!(config.network.allow_domains, vec!["pypi.org"]);
        assert!(config.network.deny_all()); // default
        assert!(config.syscalls.allow_extra.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[filesystem]
allow = ["/usr/lib"]
deny = ["/etc/shadow"]

[network]
allow_domains = ["pypi.org", "registry.npmjs.org"]
allow_ips = ["10.0.0.0/8"]
deny_all = true

[process]
max_pids = 64
allow_execve = ["/usr/bin/python3"]
env_passthrough = ["PATH", "HOME", "LANG"]

[resources]
memory_mb = 512
cpu_percent = 50

[syscalls]
seccomp_mode = "allow-list"
allow_extra = ["ptrace"]
"#;
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.resources.memory_mb, Some(512));
        assert_eq!(config.process.max_pids, Some(64));
        assert_eq!(config.syscalls.allow_extra, vec!["ptrace"]);
        assert_eq!(config.syscalls.seccomp_mode(), SeccompMode::AllowList);
    }

    #[test]
    fn default_deny_config() {
        let config = SandboxConfig::default_deny();
        assert!(config.network.deny_all());
        assert!(config.filesystem.allow.is_empty());
        assert!(config.network.allow_domains.is_empty());
        assert!(config.syscalls.allow_extra.is_empty());
        assert!(config.syscalls.deny_extra.is_empty());
    }

    #[test]
    fn reject_unknown_fields() {
        let toml = r#"
[filesystem]
allow = ["/tmp"]
bogus_field = true
"#;
        let result: Result<RecipeFile, _> = toml::from_str(toml);
        assert!(result.is_err());
    }

    // ---- Recipe tests ----

    #[test]
    fn parse_recipe_with_metadata() {
        let toml = r#"
[recipe]
name = "python-pip"
description = "Install Python packages with pip"
version = "1"

[filesystem]
allow = ["/usr/lib", "/tmp"]

[network]
allow_domains = ["pypi.org", "files.pythonhosted.org"]
deny_all = true

[process]
env_passthrough = ["PATH", "HOME"]
"#;
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        assert_eq!(recipe.display_name("fallback"), "python-pip");
        assert_eq!(recipe.description(), "Install Python packages with pip");

        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.filesystem.allow.len(), 2);
    }

    #[test]
    fn parse_recipe_without_metadata() {
        // A recipe file without [recipe] is a valid plain policy.
        let toml = r#"
[filesystem]
allow = ["/usr/lib"]

[syscalls]
allow_extra = ["ptrace"]
"#;
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        assert!(recipe.recipe.is_none());
        assert_eq!(recipe.display_name("fallback"), "fallback");

        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.syscalls.allow_extra, vec!["ptrace"]);
    }

    #[test]
    fn parse_recipe_with_syscall_overrides() {
        let toml = r#"
[recipe]
name = "elixir-dev"

[syscalls]
allow_extra = ["ptrace"]
deny_extra = ["personality", "seccomp"]
"#;
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.syscalls.allow_extra, vec!["ptrace"]);
        assert_eq!(config.syscalls.deny_extra, vec!["personality", "seccomp"]);
    }

    #[test]
    fn recipe_defaults_to_empty_overrides() {
        let toml = "";
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        let config = recipe.into_sandbox_config().unwrap();
        assert!(config.syscalls.allow_extra.is_empty());
        assert!(config.syscalls.deny_extra.is_empty());
        assert_eq!(config.syscalls.seccomp_mode(), SeccompMode::AllowList);
    }

    #[test]
    fn reject_unknown_baseline_field() {
        // "baseline" no longer exists in RecipeMeta
        let toml = r#"
[recipe]
name = "test"
baseline = "python"
"#;
        let result: Result<RecipeFile, _> = toml::from_str(toml);
        assert!(result.is_err(), "baseline field should be rejected");
    }

    #[test]
    fn reject_profile_section() {
        // [profile] section no longer exists
        let toml = r#"
[profile]
name = "python"
"#;
        let result: Result<RecipeFile, _> = toml::from_str(toml);
        assert!(result.is_err(), "[profile] section should be rejected");
    }

    // ---- Baseline (allow/deny) tests ----

    #[test]
    fn parse_baseline_with_absolute_lists() {
        let toml = r#"
[recipe]
name = "default"

[syscalls]
allow = ["read", "write", "exit_group"]
deny = ["reboot", "mount"]
"#;
        let recipe = RecipeFile::from_str(toml).unwrap();
        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.syscalls.allow, vec!["read", "write", "exit_group"]);
        assert_eq!(config.syscalls.deny, vec!["reboot", "mount"]);
        assert!(config.syscalls.allow_extra.is_empty());
        assert!(config.syscalls.deny_extra.is_empty());
        assert!(config.syscalls.is_baseline());
        assert!(!config.syscalls.is_override());
    }

    #[test]
    fn reject_mixed_absolute_and_relative() {
        let toml = r#"
[syscalls]
allow = ["read", "write"]
allow_extra = ["ptrace"]
"#;
        let result = RecipeFile::from_str(toml);
        assert!(result.is_err(), "mixing allow and allow_extra should fail");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cannot mix"),
            "error should mention mutual exclusion: {err}"
        );
    }

    #[test]
    fn reject_mixed_deny_and_deny_extra() {
        let toml = r#"
[syscalls]
deny = ["reboot"]
deny_extra = ["ptrace"]
"#;
        let result = RecipeFile::from_str(toml);
        assert!(result.is_err(), "mixing deny and deny_extra should fail");
    }

    #[test]
    fn reject_mixed_allow_and_deny_extra() {
        let toml = r#"
[syscalls]
allow = ["read", "write"]
deny_extra = ["ptrace"]
"#;
        let result = RecipeFile::from_str(toml);
        assert!(result.is_err(), "mixing allow and deny_extra should fail");
    }

    #[test]
    fn empty_syscalls_is_neither_baseline_nor_override() {
        let config = SyscallConfig::default();
        assert!(!config.is_baseline());
        assert!(!config.is_override());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn parse_default_toml_as_baseline() {
        // Verify the actual default.toml can be parsed as a baseline.
        let content = include_str!("../../../recipes/default.toml");
        let recipe = RecipeFile::from_str(content).unwrap();
        assert_eq!(recipe.display_name("fallback"), "default");
        let config = recipe.into_sandbox_config().unwrap();
        assert!(config.syscalls.is_baseline());
        assert!(!config.syscalls.is_override());
        assert!(
            config.syscalls.allow.len() > 100,
            "default baseline should have >100 allowed syscalls, got {}",
            config.syscalls.allow.len()
        );
        assert!(
            config.syscalls.deny.len() >= 16,
            "default baseline should have >=16 denied syscalls, got {}",
            config.syscalls.deny.len()
        );
    }

    // ---- Merge tests ----

    /// Helper to create a minimal recipe from TOML.
    fn parse_recipe(toml: &str) -> RecipeFile {
        RecipeFile::from_str(toml).unwrap()
    }

    #[test]
    fn merge_filesystem_union() {
        let base = parse_recipe(
            r#"
[filesystem]
allow = ["/usr/lib", "/usr/bin"]
deny = ["/etc/shadow"]
"#,
        );
        let overlay = parse_recipe(
            r#"
[filesystem]
allow = ["/usr/bin", "/tmp/workspace"]
deny = ["/root"]
"#,
        );
        let merged = base.merge(overlay);
        assert_eq!(
            merged.filesystem.allow,
            vec![
                PathBuf::from("/usr/lib"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/tmp/workspace"),
            ]
        );
        assert_eq!(
            merged.filesystem.deny,
            vec![PathBuf::from("/etc/shadow"), PathBuf::from("/root")]
        );
    }

    #[test]
    fn merge_strict_or_semantics() {
        // None + None = None (resolved to false)
        let a = parse_recipe("");
        let b = parse_recipe("");
        assert_eq!(a.merge(b).strict, None);

        // None + Some(false) = Some(false)
        let a = parse_recipe("");
        let b = parse_recipe("strict = false");
        assert_eq!(a.merge(b).strict, Some(false));

        // Some(false) + Some(true) = Some(true) (OR)
        let a = parse_recipe("strict = false");
        let b = parse_recipe("strict = true");
        assert_eq!(a.merge(b).strict, Some(true));

        // Some(true) + Some(false) = Some(true) (OR — true can never be overridden)
        let a = parse_recipe("strict = true");
        let b = parse_recipe("strict = false");
        assert_eq!(a.merge(b).strict, Some(true));

        // Some(true) + None = Some(true)
        let a = parse_recipe("strict = true");
        let b = parse_recipe("");
        assert_eq!(a.merge(b).strict, Some(true));
    }

    #[test]
    fn merge_deny_all_last_wins() {
        // None + None = None (resolved to true by default)
        let a = parse_recipe("");
        let b = parse_recipe("");
        assert_eq!(a.merge(b).network.deny_all, None);

        // None + Some(false) = Some(false)
        let a = parse_recipe("");
        let b = parse_recipe("[network]\ndeny_all = false");
        assert_eq!(a.merge(b).network.deny_all, Some(false));

        // Some(true) + Some(false) = Some(false) (last wins)
        let a = parse_recipe("[network]\ndeny_all = true");
        let b = parse_recipe("[network]\ndeny_all = false");
        assert_eq!(a.merge(b).network.deny_all, Some(false));

        // Some(false) + None = Some(false) (None preserves base)
        let a = parse_recipe("[network]\ndeny_all = false");
        let b = parse_recipe("");
        assert_eq!(a.merge(b).network.deny_all, Some(false));
    }

    #[test]
    fn merge_network_domains_union() {
        let a = parse_recipe(
            r#"
[network]
allow_domains = ["pypi.org", "github.com"]
"#,
        );
        let b = parse_recipe(
            r#"
[network]
allow_domains = ["github.com", "hex.pm"]
"#,
        );
        let merged = a.merge(b);
        assert_eq!(
            merged.network.allow_domains,
            vec!["pypi.org", "github.com", "hex.pm"]
        );
    }

    #[test]
    fn merge_seccomp_mode_last_wins() {
        let a = parse_recipe(
            r#"
[syscalls]
seccomp_mode = "allow-list"
"#,
        );
        let b = parse_recipe(
            r#"
[syscalls]
seccomp_mode = "deny-list"
"#,
        );
        assert_eq!(
            a.merge(b).syscalls.seccomp_mode,
            Some(SeccompMode::DenyList)
        );

        // None preserves base.
        let a = parse_recipe(
            r#"
[syscalls]
seccomp_mode = "deny-list"
"#,
        );
        let b = parse_recipe("");
        assert_eq!(
            a.merge(b).syscalls.seccomp_mode,
            Some(SeccompMode::DenyList)
        );
    }

    #[test]
    fn merge_syscall_extras_union() {
        let a = parse_recipe(
            r#"
[syscalls]
allow_extra = ["ptrace", "personality"]
deny_extra = ["reboot"]
"#,
        );
        let b = parse_recipe(
            r#"
[syscalls]
allow_extra = ["personality", "seccomp"]
deny_extra = ["mount"]
"#,
        );
        let merged = a.merge(b);
        assert_eq!(
            merged.syscalls.allow_extra,
            vec!["ptrace", "personality", "seccomp"]
        );
        assert_eq!(merged.syscalls.deny_extra, vec!["reboot", "mount"]);
    }

    #[test]
    fn merge_resources_last_wins() {
        let a = parse_recipe(
            r#"
[resources]
memory_mb = 512
cpu_percent = 50
"#,
        );
        let b = parse_recipe(
            r#"
[resources]
memory_mb = 1024
"#,
        );
        let merged = a.merge(b);
        assert_eq!(merged.resources.memory_mb, Some(1024)); // overlay wins
        assert_eq!(merged.resources.cpu_percent, Some(50)); // base preserved
    }

    #[test]
    fn merge_process_union_and_last_wins() {
        let a = parse_recipe(
            r#"
[process]
max_pids = 64
allow_execve = ["/usr/bin/python3"]
env_passthrough = ["PATH", "HOME"]
"#,
        );
        let b = parse_recipe(
            r#"
[process]
max_pids = 256
env_passthrough = ["HOME", "LANG"]
"#,
        );
        let merged = a.merge(b);
        assert_eq!(merged.process.max_pids, Some(256)); // last wins
        assert_eq!(merged.process.env_passthrough, vec!["PATH", "HOME", "LANG"]); // union
        assert_eq!(
            merged.process.allow_execve,
            vec![PathBuf::from("/usr/bin/python3")]
        ); // preserved
    }

    #[test]
    fn merge_recipe_meta_overlay_wins() {
        let a = parse_recipe(
            r#"
[recipe]
name = "base"
description = "base recipe"
"#,
        );
        let b = parse_recipe(
            r#"
[recipe]
name = "overlay"
description = "overlay recipe"
"#,
        );
        let merged = a.merge(b);
        assert_eq!(merged.display_name("fallback"), "overlay");
        assert_eq!(merged.description(), "overlay recipe");
    }

    #[test]
    fn merge_three_recipes() {
        let a = parse_recipe(
            r#"
[filesystem]
allow = ["/usr/lib"]
"#,
        );
        let b = parse_recipe(
            r#"
[filesystem]
allow = ["/usr/bin"]

[syscalls]
allow_extra = ["ptrace"]
"#,
        );
        let c = parse_recipe(
            r#"
strict = true

[filesystem]
allow = ["/tmp"]
deny = ["/root"]
"#,
        );
        let merged = a.merge(b).merge(c);
        assert_eq!(
            merged.filesystem.allow,
            vec![
                PathBuf::from("/usr/lib"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/tmp"),
            ]
        );
        assert_eq!(merged.filesystem.deny, vec![PathBuf::from("/root")]);
        assert_eq!(merged.syscalls.allow_extra, vec!["ptrace"]);
        assert_eq!(merged.strict, Some(true));
    }

    #[test]
    fn merge_match_prefix_preserved() {
        let a = parse_recipe(
            r#"
[recipe]
name = "nix"
match_prefix = ["/nix/store"]
"#,
        );
        // Overlay with different recipe replaces metadata.
        let b = parse_recipe(
            r#"
[recipe]
name = "elixir"
"#,
        );
        let merged = a.merge(b);
        // Overlay metadata wins (elixir has no match_prefix).
        assert_eq!(merged.display_name("fallback"), "elixir");
        assert!(merged.match_prefixes().is_empty());
    }

    // ---------------------------------------------------------------
    // Environment variable expansion tests
    // ---------------------------------------------------------------
    // Environment variable expansion tests
    //
    // SAFETY: Tests use unique variable names prefixed with _CANISTER_TEST_
    // and are not safety-critical. The unsafe blocks are needed because
    // Rust 2024 marks set_var/remove_var as unsafe (not thread-safe).
    // ---------------------------------------------------------------

    #[test]
    fn expand_env_vars_no_vars() {
        assert_eq!(expand_env_vars("/usr/lib"), "/usr/lib");
    }

    #[test]
    fn expand_env_vars_home() {
        // SAFETY: unique test-only env var, no concurrent readers.
        unsafe { std::env::set_var("_CANISTER_TEST_HOME", "/home/testuser") };
        assert_eq!(
            expand_env_vars("$_CANISTER_TEST_HOME/.cargo/bin"),
            "/home/testuser/.cargo/bin"
        );
        unsafe { std::env::remove_var("_CANISTER_TEST_HOME") };
    }

    #[test]
    fn expand_env_vars_braced() {
        unsafe { std::env::set_var("_CANISTER_TEST_USER", "alice") };
        assert_eq!(
            expand_env_vars("/home/${_CANISTER_TEST_USER}/.local"),
            "/home/alice/.local"
        );
        unsafe { std::env::remove_var("_CANISTER_TEST_USER") };
    }

    #[test]
    fn expand_env_vars_multiple() {
        unsafe { std::env::set_var("_CT_A", "aaa") };
        unsafe { std::env::set_var("_CT_B", "bbb") };
        assert_eq!(expand_env_vars("$_CT_A/$_CT_B"), "aaa/bbb");
        unsafe { std::env::remove_var("_CT_A") };
        unsafe { std::env::remove_var("_CT_B") };
    }

    #[test]
    fn expand_env_vars_unset_becomes_empty() {
        unsafe { std::env::remove_var("_CANISTER_SURELY_UNSET") };
        assert_eq!(
            expand_env_vars("/prefix/$_CANISTER_SURELY_UNSET/suffix"),
            "/prefix//suffix"
        );
    }

    #[test]
    fn expand_env_vars_double_dollar_escapes() {
        assert_eq!(expand_env_vars("cost: $$100"), "cost: $100");
    }

    #[test]
    fn expand_env_vars_lone_dollar_preserved() {
        assert_eq!(expand_env_vars("a $ b"), "a $ b");
    }

    #[test]
    fn expand_env_vars_in_sandbox_config() {
        unsafe { std::env::set_var("_CANISTER_TEST_HOME2", "/home/bob") };
        let recipe = parse_recipe(
            r#"
[filesystem]
allow = ["$_CANISTER_TEST_HOME2/.cargo"]
deny = ["$_CANISTER_TEST_HOME2/.ssh"]

[process]
allow_execve = ["$_CANISTER_TEST_HOME2/.cargo/bin/rustc"]
"#,
        );
        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(
            config.filesystem.allow,
            vec![PathBuf::from("/home/bob/.cargo")]
        );
        assert_eq!(
            config.filesystem.deny,
            vec![PathBuf::from("/home/bob/.ssh")]
        );
        assert_eq!(
            config.process.allow_execve,
            vec![PathBuf::from("/home/bob/.cargo/bin/rustc")]
        );
        unsafe { std::env::remove_var("_CANISTER_TEST_HOME2") };
    }

    #[test]
    fn expand_env_vars_match_prefixes_expanded() {
        unsafe { std::env::set_var("_CANISTER_TEST_HOME3", "/home/carol") };
        let recipe = parse_recipe(
            r#"
[recipe]
name = "cargo"
match_prefix = ["$_CANISTER_TEST_HOME3/.cargo"]
"#,
        );
        assert_eq!(recipe.match_prefixes(), &["$_CANISTER_TEST_HOME3/.cargo"]);
        assert_eq!(
            recipe.match_prefixes_expanded(),
            vec!["/home/carol/.cargo".to_string()]
        );
        unsafe { std::env::remove_var("_CANISTER_TEST_HOME3") };
    }
}
