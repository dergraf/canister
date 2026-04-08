use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;

/// Top-level sandbox configuration, parsed from TOML.
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

    /// Seccomp profile selection.
    #[serde(default)]
    pub profile: ProfileConfig,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    /// Name of the seccomp profile to use.
    /// Built-in profiles: "generic", "python", "node", "elixir".
    #[serde(default = "default_profile")]
    pub name: String,

    /// Seccomp enforcement mode: "allow-list" (default) or "deny-list".
    #[serde(default)]
    pub seccomp_mode: SeccompMode,
}

impl Default for ProfileConfig {
    fn default() -> Self {
        Self {
            name: default_profile(),
            seccomp_mode: SeccompMode::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_profile() -> String {
    "generic".to_string()
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
            profile: ProfileConfig::default(),
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

    #[error("unknown baseline/profile: \"{0}\" (available: generic, python, node, elixir)")]
    UnknownBaseline(String),
}

// ---------------------------------------------------------------------------
// Recipe support
// ---------------------------------------------------------------------------

/// Metadata section for recipe files.
///
/// Recipes are the primary user-facing policy format. They compose a
/// complete sandbox policy by selecting a baseline (syscall set) and
/// layering filesystem, network, process, and resource rules on top.
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

    /// Baseline syscall profile. One of: "generic", "python", "node", "elixir".
    ///
    /// When set, overrides `[profile].name`. This is the preferred way to
    /// select a syscall baseline in recipes.
    pub baseline: Option<String>,
}

/// A recipe file — superset of `SandboxConfig` with optional metadata.
///
/// This is the only entry point for parsing policy TOML files.
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

    /// Seccomp profile selection.
    #[serde(default)]
    pub profile: ProfileConfig,
}

impl RecipeFile {
    /// Load a recipe from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::ReadFile)?;
        toml::from_str(&content).map_err(ConfigError::Parse)
    }

    /// Resolve into a `SandboxConfig`, applying baseline override.
    ///
    /// If the recipe has a `[recipe] baseline = "..."`, that overrides
    /// the `[profile] name = "..."` field. The resulting profile name is
    /// validated against known baselines.
    pub fn into_sandbox_config(self) -> Result<SandboxConfig, ConfigError> {
        let mut profile = self.profile;

        // baseline takes precedence over profile.name
        if let Some(ref meta) = self.recipe {
            if let Some(ref baseline) = meta.baseline {
                profile.name = baseline.clone();
            }
        }

        // Validate the profile/baseline name resolves to a known builtin.
        if crate::SeccompProfile::builtin(&profile.name).is_none() {
            return Err(ConfigError::UnknownBaseline(profile.name));
        }

        Ok(SandboxConfig {
            strict: self.strict,
            filesystem: self.filesystem,
            network: self.network,
            process: self.process,
            resources: self.resources,
            profile,
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

    /// Get the effective baseline name (resolved).
    pub fn baseline_name(&self) -> &str {
        self.recipe
            .as_ref()
            .and_then(|m| m.baseline.as_deref())
            .unwrap_or(&self.profile.name)
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
        assert_eq!(config.profile.name, "generic"); // default
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

[profile]
name = "python"
"#;
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.resources.memory_mb, Some(512));
        assert_eq!(config.process.max_pids, Some(64));
        assert_eq!(config.profile.name, "python");
    }

    #[test]
    fn default_deny_config() {
        let config = SandboxConfig::default_deny();
        assert!(config.network.deny_all);
        assert!(config.filesystem.allow.is_empty());
        assert!(config.network.allow_domains.is_empty());
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
baseline = "python"

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
        assert_eq!(recipe.baseline_name(), "python");

        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.profile.name, "python");
        assert_eq!(config.filesystem.allow.len(), 2);
    }

    #[test]
    fn parse_recipe_without_metadata() {
        // A recipe file without [recipe] is a valid plain policy.
        let toml = r#"
[filesystem]
allow = ["/usr/lib"]

[profile]
name = "node"
"#;
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        assert!(recipe.recipe.is_none());
        assert_eq!(recipe.display_name("fallback"), "fallback");
        assert_eq!(recipe.baseline_name(), "node");

        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.profile.name, "node");
    }

    #[test]
    fn recipe_baseline_overrides_profile_name() {
        let toml = r#"
[recipe]
baseline = "elixir"

[profile]
name = "generic"
seccomp_mode = "allow-list"
"#;
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        let config = recipe.into_sandbox_config().unwrap();
        // baseline wins over profile.name
        assert_eq!(config.profile.name, "elixir");
        // seccomp_mode preserved
        assert_eq!(config.profile.seccomp_mode, SeccompMode::AllowList);
    }

    #[test]
    fn recipe_unknown_baseline_rejected() {
        let toml = r#"
[recipe]
baseline = "nonexistent"
"#;
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        let result = recipe.into_sandbox_config();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn recipe_defaults_to_generic() {
        let toml = "";
        let recipe: RecipeFile = toml::from_str(toml).unwrap();
        let config = recipe.into_sandbox_config().unwrap();
        assert_eq!(config.profile.name, "generic");
    }
}
