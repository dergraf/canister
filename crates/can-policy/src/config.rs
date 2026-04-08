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

impl std::str::FromStr for SandboxConfig {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        toml::from_str(s).map_err(ConfigError::Parse)
    }
}

impl SandboxConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::ReadFile)?;
        content.parse()
    }

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
        let config: SandboxConfig = toml.parse().unwrap();
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
        let config: SandboxConfig = toml.parse().unwrap();
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
        let result: Result<SandboxConfig, _> = toml.parse();
        assert!(result.is_err());
    }
}
