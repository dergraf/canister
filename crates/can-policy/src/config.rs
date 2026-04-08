use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;

/// Top-level sandbox configuration.
///
/// This is the resolved, validated form used by the sandbox runtime.
/// Produced from `RecipeFile::into_sandbox_config()`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Strict mode: fail hard instead of degrading gracefully.
    ///
    /// When true, any setup failure (filesystem isolation, seccomp, cgroups)
    /// is a fatal error instead of a warning. Seccomp uses KILL_PROCESS
    /// instead of ERRNO. Intended for CI / production use.
    #[serde(default)]
    pub strict: bool,

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

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    /// Paths the sandboxed process is allowed to access.
    #[serde(default)]
    pub allow: Vec<PathBuf>,

    /// Paths explicitly denied (checked before allow).
    #[serde(default)]
    pub deny: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Whitelisted domain names (resolved via internal DNS proxy).
    #[serde(default)]
    pub allow_domains: Vec<String>,

    /// Whitelisted IP addresses or CIDR ranges.
    #[serde(default)]
    pub allow_ips: Vec<String>,

    /// If true, deny all network access except explicitly allowed.
    /// Defaults to true (secure by default).
    #[serde(default = "default_true")]
    pub deny_all: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            allow_domains: Vec::new(),
            allow_ips: Vec::new(),
            deny_all: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
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

#[derive(Debug, Clone, Deserialize, Default)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
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
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SyscallConfig {
    /// Seccomp enforcement mode: "allow-list" (default) or "deny-list".
    #[serde(default)]
    pub seccomp_mode: SeccompMode,

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

fn default_true() -> bool {
    true
}

impl SandboxConfig {
    /// Return a default config with sensible defaults (deny-all).
    pub fn default_deny() -> Self {
        Self {
            strict: false,
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
}

/// A recipe file — the only entry point for parsing policy TOML files.
///
/// Files without a `[recipe]` section are valid — the field defaults
/// to `None` and the file is treated as a plain policy.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeFile {
    /// Recipe metadata (optional).
    #[serde(default)]
    pub recipe: Option<RecipeMeta>,

    /// Strict mode: fail hard instead of degrading gracefully.
    #[serde(default)]
    pub strict: bool,

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
    pub fn into_sandbox_config(self) -> Result<SandboxConfig, ConfigError> {
        Ok(SandboxConfig {
            strict: self.strict,
            filesystem: self.filesystem,
            network: self.network,
            process: self.process,
            resources: self.resources,
            syscalls: self.syscalls,
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
        assert!(config.network.deny_all); // default
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
        assert_eq!(config.syscalls.seccomp_mode, SeccompMode::AllowList);
    }

    #[test]
    fn default_deny_config() {
        let config = SandboxConfig::default_deny();
        assert!(config.network.deny_all);
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
        assert_eq!(config.syscalls.seccomp_mode, SeccompMode::AllowList);
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
            config.syscalls.deny.len() >= 14,
            "default baseline should have >=14 denied syscalls, got {}",
            config.syscalls.deny.len()
        );
    }
}
