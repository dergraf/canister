use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::filesystem::FilesystemConfig;
use super::network::NetworkConfig;
use super::process::ProcessConfig;
use super::proxy::ProxyConfig;
use super::resources::ResourceConfig;
use super::syscalls::SyscallConfig;

/// Top-level sandbox configuration.
///
/// This is the resolved, validated form used by the sandbox runtime.
/// All `Option` fields are guaranteed to be `Some` after resolution
/// via `RecipeFile::into_sandbox_config()`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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

    /// L7 Proxy and interception configuration.
    #[serde(default)]
    pub proxy: ProxyConfig,
}

impl SandboxConfig {
    /// Return a default config with sensible defaults (proxy-only egress).
    pub fn default_deny() -> Self {
        Self {
            strict: false,
            filesystem: FilesystemConfig::default(),
            network: NetworkConfig::default(),
            process: ProcessConfig::default(),
            resources: ResourceConfig::default(),
            syscalls: SyscallConfig::default(),
            proxy: ProxyConfig::default(),
        }
    }
}
