use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FilesystemConfig {
    /// Paths the sandboxed process is allowed to access (read-only).
    #[serde(default)]
    pub allow: Vec<PathBuf>,

    /// Paths bind-mounted writable into the sandbox.
    ///
    /// Use this for directories the sandboxed process must write to
    /// (e.g., database files, caches, state directories). These paths
    /// are mounted writable — changes persist on the host.
    #[serde(default)]
    pub allow_write: Vec<PathBuf>,

    /// Paths explicitly denied (checked before allow and allow_write).
    #[serde(default)]
    pub deny: Vec<PathBuf>,

    /// Paths to mask inside the sandbox (bind `/dev/null` over them).
    ///
    /// Used to hide files that would otherwise be visible through the
    /// CWD bind-mount. For example, `canister.toml` is auto-masked
    /// when running via `can up` to prevent the sandboxed process from
    /// reading the security policy.
    ///
    /// This field is set programmatically by the CLI layer and is not
    /// expected in recipe TOML files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mask: Vec<PathBuf>,
}

/// Protocol for port forwarding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    #[default]
    Tcp,
    Udp,
}

impl fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

/// A port forwarding rule mapping a host port to a container port.
///
/// Follows Docker/Podman syntax: `[ip:]hostPort:containerPort[/protocol]`
///
/// Examples:
/// - `8080:80` — TCP, host 8080 → container 80
/// - `8080:80/udp` — UDP, host 8080 → container 80
/// - `127.0.0.1:8080:80` — TCP, bind to 127.0.0.1, host 8080 → container 80
/// - `8080:8080` or just `8080` (shorthand) — TCP, same port both sides
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortMapping {
    /// Optional IP address to bind on the host side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ip: Option<IpAddr>,

    /// Port on the host.
    pub host_port: u16,

    /// Port inside the container/sandbox.
    pub container_port: u16,

    /// Protocol (tcp or udp). Defaults to tcp.
    #[serde(default)]
    pub protocol: PortProtocol,
}

impl fmt::Display for PortMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ip) = &self.host_ip {
            write!(f, "{ip}:")?;
        }
        write!(
            f,
            "{}:{}/{}",
            self.host_port, self.container_port, self.protocol
        )
    }
}

impl PortMapping {
    /// Parse a port mapping from Docker/Podman syntax.
    ///
    /// Supported formats:
    /// - `port` — shorthand for `port:port/tcp`
    /// - `hostPort:containerPort` — defaults to tcp
    /// - `hostPort:containerPort/protocol`
    /// - `ip:hostPort:containerPort`
    /// - `ip:hostPort:containerPort/protocol`
    pub fn parse(s: &str) -> Result<Self, String> {
        // Split off protocol suffix.
        let (addr_part, protocol) = if let Some((addr, proto)) = s.rsplit_once('/') {
            let protocol = match proto {
                "tcp" => PortProtocol::Tcp,
                "udp" => PortProtocol::Udp,
                other => return Err(format!("unknown protocol: {other}")),
            };
            (addr, protocol)
        } else {
            (s, PortProtocol::Tcp)
        };

        let parts: Vec<&str> = addr_part.split(':').collect();
        match parts.len() {
            1 => {
                // Single port: same on both sides.
                let port: u16 = parts[0]
                    .parse()
                    .map_err(|e| format!("invalid port '{}': {e}", parts[0]))?;
                Ok(PortMapping {
                    host_ip: None,
                    host_port: port,
                    container_port: port,
                    protocol,
                })
            }
            2 => {
                // hostPort:containerPort
                let host_port: u16 = parts[0]
                    .parse()
                    .map_err(|e| format!("invalid host port '{}': {e}", parts[0]))?;
                let container_port: u16 = parts[1]
                    .parse()
                    .map_err(|e| format!("invalid container port '{}': {e}", parts[1]))?;
                Ok(PortMapping {
                    host_ip: None,
                    host_port,
                    container_port,
                    protocol,
                })
            }
            3 => {
                // ip:hostPort:containerPort
                let host_ip: IpAddr = parts[0]
                    .parse()
                    .map_err(|e| format!("invalid IP '{}': {e}", parts[0]))?;
                let host_port: u16 = parts[1]
                    .parse()
                    .map_err(|e| format!("invalid host port '{}': {e}", parts[1]))?;
                let container_port: u16 = parts[2]
                    .parse()
                    .map_err(|e| format!("invalid container port '{}': {e}", parts[2]))?;
                Ok(PortMapping {
                    host_ip: Some(host_ip),
                    host_port,
                    container_port,
                    protocol,
                })
            }
            _ => Err(format!("invalid port mapping: {s}")),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Egress mode controls outbound networking behavior.
    ///
    /// - `proxy-only` (default): outbound traffic must go through local proxy
    /// - `none`: no outbound networking
    /// - `direct`: direct outbound allowed, still policy-checked
    #[serde(default)]
    pub egress: Option<EgressMode>,

    /// Allowed domain names (resolved via internal DNS proxy).
    #[serde(default)]
    pub allow_domains: Vec<String>,

    /// Allowed IP addresses or CIDR ranges.
    #[serde(default)]
    pub allow_ips: Vec<String>,

    /// Port forwarding rules: map host ports to sandbox ports.
    ///
    /// Uses Docker/Podman syntax: `[ip:]hostPort:containerPort[/protocol]`.
    /// Supported when `egress != direct` (filtered networking).
    /// Forwarded ports are accessible from the host to the sandbox.
    #[serde(default)]
    pub ports: Vec<PortMapping>,
}

impl NetworkConfig {
    /// Return the effective egress mode (defaults to proxy-only).
    pub fn egress(&self) -> EgressMode {
        self.egress.unwrap_or(EgressMode::ProxyOnly)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EgressMode {
    None,
    ProxyOnly,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Map of target domains to intercept -> path to Wasm plugin.
    #[serde(default)]
    pub interceptors: std::collections::HashMap<String, PathBuf>,

    /// Maximum bytes buffered when a Wasm hook returns `buffer_body=true`.
    /// Requests/responses exceeding the cap get a 413 (request) or are
    /// truncated/aborted (response). Defaults to 8 MiB.
    #[serde(default)]
    pub max_buffered_body_bytes: Option<usize>,

    /// Per-hook Wasm execution timeout in milliseconds. Plugins exceeding it
    /// are cancelled and the request fails with 502. Defaults to 200 ms.
    #[serde(default)]
    pub wasm_hook_timeout_ms: Option<u64>,

    /// Upstream request total timeout in milliseconds. Defaults to 30 000 ms.
    #[serde(default)]
    pub upstream_request_timeout_ms: Option<u64>,
}

impl ProxyConfig {
    pub const DEFAULT_MAX_BUFFERED_BODY_BYTES: usize = 8 * 1024 * 1024;
    pub const DEFAULT_WASM_HOOK_TIMEOUT_MS: u64 = 200;
    pub const DEFAULT_UPSTREAM_REQUEST_TIMEOUT_MS: u64 = 30_000;

    pub fn max_buffered_body_bytes(&self) -> usize {
        self.max_buffered_body_bytes
            .unwrap_or(Self::DEFAULT_MAX_BUFFERED_BODY_BYTES)
    }

    pub fn wasm_hook_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.wasm_hook_timeout_ms
                .unwrap_or(Self::DEFAULT_WASM_HOOK_TIMEOUT_MS),
        )
    }

    pub fn upstream_request_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.upstream_request_timeout_ms
                .unwrap_or(Self::DEFAULT_UPSTREAM_REQUEST_TIMEOUT_MS),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
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

    /// Environment variables to set in the sandbox.
    /// These are evaluated after passthrough.
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
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
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(ConfigError::ReadFile)?;
        Self::parse(&content)
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
                allow: self
                    .filesystem
                    .allow
                    .into_iter()
                    .map(|p| PathBuf::from(expand_env_vars(&p.to_string_lossy())))
                    .collect(),
                allow_write: self
                    .filesystem
                    .allow_write
                    .into_iter()
                    .map(|p| PathBuf::from(expand_env_vars(&p.to_string_lossy())))
                    .collect(),
                deny: self
                    .filesystem
                    .deny
                    .into_iter()
                    .map(|p| PathBuf::from(expand_env_vars(&p.to_string_lossy())))
                    .collect(),
                mask: self.filesystem.mask,
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
                env: self.process.env,
            },
            resources: self.resources,
            syscalls: self.syscalls,
            proxy: ProxyConfig {
                interceptors: self
                    .proxy
                    .interceptors
                    .into_iter()
                    .map(|(k, p)| (k, PathBuf::from(expand_env_vars(&p.to_string_lossy()))))
                    .collect(),
                max_buffered_body_bytes: self.proxy.max_buffered_body_bytes,
                wasm_hook_timeout_ms: self.proxy.wasm_hook_timeout_ms,
                upstream_request_timeout_ms: self.proxy.upstream_request_timeout_ms,
            },
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

            // Filesystem: union of paths.
            filesystem: FilesystemConfig {
                allow: union_vecs(self.filesystem.allow, overlay.filesystem.allow),
                allow_write: union_vecs(
                    self.filesystem.allow_write,
                    overlay.filesystem.allow_write,
                ),
                deny: union_vecs(self.filesystem.deny, overlay.filesystem.deny),
                mask: union_vecs(self.filesystem.mask, overlay.filesystem.mask),
            },

            // Network: union of lists, egress is last-Some-wins.
            network: NetworkConfig {
                egress: overlay.network.egress.or(self.network.egress),
                allow_domains: union_vecs(
                    self.network.allow_domains,
                    overlay.network.allow_domains,
                ),
                allow_ips: union_vecs(self.network.allow_ips, overlay.network.allow_ips),
                ports: union_vecs(self.network.ports, overlay.network.ports),
            },

            // Process: union of lists, max_pids is last-Some-wins.
            process: ProcessConfig {
                max_pids: overlay.process.max_pids.or(self.process.max_pids),
                allow_execve: union_vecs(self.process.allow_execve, overlay.process.allow_execve),
                env_passthrough: union_vecs(
                    self.process.env_passthrough,
                    overlay.process.env_passthrough,
                ),
                env: {
                    let mut env = self.process.env;
                    env.extend(overlay.process.env);
                    env
                },
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

            // Proxy: enabled is last-Some-wins, interceptors are merged.
            proxy: ProxyConfig {
                interceptors: {
                    let mut m = self.proxy.interceptors;
                    m.extend(overlay.proxy.interceptors);
                    m
                },
                max_buffered_body_bytes: overlay
                    .proxy
                    .max_buffered_body_bytes
                    .or(self.proxy.max_buffered_body_bytes),
                wasm_hook_timeout_ms: overlay
                    .proxy
                    .wasm_hook_timeout_ms
                    .or(self.proxy.wasm_hook_timeout_ms),
                upstream_request_timeout_ms: overlay
                    .proxy
                    .upstream_request_timeout_ms
                    .or(self.proxy.upstream_request_timeout_ms),
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
        assert_eq!(config.network.egress(), EgressMode::ProxyOnly); // default
        assert!(config.syscalls.allow_extra.is_empty());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[filesystem]
allow = ["/usr/lib"]
allow_write = ["/var/data"]
deny = ["/etc/shadow"]

[network]
allow_domains = ["pypi.org", "registry.npmjs.org"]
allow_ips = ["10.0.0.0/8"]
egress = "proxy-only"

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
        assert_eq!(
            config.filesystem.allow_write,
            vec![PathBuf::from("/var/data")]
        );
    }

    #[test]
    fn default_deny_config() {
        let config = SandboxConfig::default_deny();
        assert_eq!(config.network.egress(), EgressMode::ProxyOnly);
        assert!(config.filesystem.allow.is_empty());
        assert!(config.network.allow_domains.is_empty());
        assert!(config.syscalls.allow_extra.is_empty());
        assert!(config.syscalls.deny_extra.is_empty());
    }

    #[test]
    fn egress_default_is_proxy_only() {
        let network = NetworkConfig::default();
        assert_eq!(network.egress(), EgressMode::ProxyOnly);
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
egress = "proxy-only"

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
        let recipe = RecipeFile::parse(toml).unwrap();
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
        let result = RecipeFile::parse(toml);
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
        let result = RecipeFile::parse(toml);
        assert!(result.is_err(), "mixing deny and deny_extra should fail");
    }

    #[test]
    fn reject_mixed_allow_and_deny_extra() {
        let toml = r#"
[syscalls]
allow = ["read", "write"]
deny_extra = ["ptrace"]
"#;
        let result = RecipeFile::parse(toml);
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
        let recipe = RecipeFile::parse(content).unwrap();
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
        RecipeFile::parse(toml).unwrap()
    }

    #[test]
    fn merge_filesystem_union() {
        let base = parse_recipe(
            r#"
[filesystem]
allow = ["/usr/lib", "/usr/bin"]
allow_write = ["/tmp/state"]
deny = ["/etc/shadow"]
"#,
        );
        let overlay = parse_recipe(
            r#"
[filesystem]
allow = ["/usr/bin", "/tmp/workspace"]
allow_write = ["/tmp/state", "/var/cache/app"]
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
            merged.filesystem.allow_write,
            vec![PathBuf::from("/tmp/state"), PathBuf::from("/var/cache/app"),]
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
    fn merge_egress_last_wins() {
        // None + None = None (resolved to proxy-only by default)
        let a = parse_recipe("");
        let b = parse_recipe("");
        assert_eq!(a.merge(b).network.egress, None);

        // None + Some(direct) = Some(direct)
        let a = parse_recipe("");
        let b = parse_recipe("[network]\negress = \"direct\"");
        assert_eq!(a.merge(b).network.egress, Some(EgressMode::Direct));

        // proxy-only + direct = direct (last wins)
        let a = parse_recipe("[network]\negress = \"proxy-only\"");
        let b = parse_recipe("[network]\negress = \"direct\"");
        assert_eq!(a.merge(b).network.egress, Some(EgressMode::Direct));

        // direct + None = direct (None preserves base)
        let a = parse_recipe("[network]\negress = \"direct\"");
        let b = parse_recipe("");
        assert_eq!(a.merge(b).network.egress, Some(EgressMode::Direct));
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
    fn merge_three_recipes_any_strict_true_wins() {
        // strict=true sticky across the chain in every position.
        let strict_first = parse_recipe("strict = true")
            .merge(parse_recipe(""))
            .merge(parse_recipe("strict = false"));
        assert_eq!(strict_first.strict, Some(true), "strict=true in slot 0");

        let strict_middle = parse_recipe("")
            .merge(parse_recipe("strict = true"))
            .merge(parse_recipe("strict = false"));
        assert_eq!(strict_middle.strict, Some(true), "strict=true in slot 1");

        let strict_last = parse_recipe("strict = false")
            .merge(parse_recipe(""))
            .merge(parse_recipe("strict = true"));
        assert_eq!(strict_last.strict, Some(true), "strict=true in slot 2");
    }

    #[test]
    fn merge_three_recipes_egress_chain_last_wins() {
        // egress: None + Direct + ProxyOnly → ProxyOnly (last wins)
        let merged = parse_recipe("")
            .merge(parse_recipe(
                r#"
[network]
egress = "direct"
"#,
            ))
            .merge(parse_recipe(
                r#"
[network]
egress = "proxy-only"
"#,
            ));
        assert_eq!(merged.network.egress, Some(EgressMode::ProxyOnly));

        // egress: ProxyOnly + None-set + Direct → Direct (last non-None
        // value wins; an "empty" recipe doesn't reset to None)
        let merged = parse_recipe(
            r#"
[network]
egress = "proxy-only"
"#,
        )
        .merge(parse_recipe(""))
        .merge(parse_recipe(
            r#"
[network]
egress = "direct"
"#,
        ));
        assert_eq!(merged.network.egress, Some(EgressMode::Direct));
    }

    #[test]
    fn merge_three_recipes_allow_extra_union_dedupes() {
        // Same syscall named in two different recipes must dedupe.
        let merged = parse_recipe(
            r#"
[syscalls]
allow_extra = ["ptrace"]
"#,
        )
        .merge(parse_recipe(
            r#"
[syscalls]
allow_extra = ["ptrace", "io_uring_setup"]
"#,
        ))
        .merge(parse_recipe(
            r#"
[syscalls]
allow_extra = ["io_uring_setup", "io_uring_enter"]
"#,
        ));
        // Union semantics + insertion-order preservation. dedup must
        // not produce ["ptrace", "ptrace", "io_uring_setup", ...].
        assert_eq!(merged.syscalls.allow_extra.len(), 3);
        for s in ["ptrace", "io_uring_setup", "io_uring_enter"] {
            assert!(
                merged.syscalls.allow_extra.contains(&s.to_string()),
                "{s} missing from merged allow_extra",
            );
        }
    }

    #[test]
    fn merge_recipe_with_allow_and_deny_extra_keeps_both() {
        // Intra-recipe contradiction: same syscall in both allow_extra
        // and deny_extra. The merge layer faithfully unions both lists;
        // the actual conflict resolution (deny wins) is enforced later
        // by SeccompProfile::apply_overrides.
        let merged = parse_recipe(
            r#"
[syscalls]
allow_extra = ["ptrace"]
deny_extra = ["ptrace"]
"#,
        );
        assert!(merged.syscalls.allow_extra.contains(&"ptrace".to_string()));
        assert!(merged.syscalls.deny_extra.contains(&"ptrace".to_string()));
    }

    #[test]
    fn merge_three_recipes_strict_invariant_with_egress_change() {
        // Realistic three-way chain: a strict baseline, an auto-detected
        // recipe that loosens egress, and an explicit -r that adds
        // domains. strict should remain Some(true).
        let strict_base = parse_recipe(
            r#"
strict = true

[network]
egress = "proxy-only"
"#,
        );
        let auto_detected = parse_recipe(
            r#"
[network]
allow_domains = ["github.com"]
"#,
        );
        let cli_override = parse_recipe(
            r#"
[network]
allow_domains = ["registry.npmjs.org"]
"#,
        );
        let merged = strict_base.merge(auto_detected).merge(cli_override);
        assert_eq!(merged.strict, Some(true));
        assert_eq!(merged.network.egress, Some(EgressMode::ProxyOnly));
        // Both domains union into the final allow list.
        assert!(
            merged
                .network
                .allow_domains
                .iter()
                .any(|d| d == "github.com")
        );
        assert!(
            merged
                .network
                .allow_domains
                .iter()
                .any(|d| d == "registry.npmjs.org")
        );
    }

    #[test]
    fn merge_proxy_interceptors_overlay_overrides_per_key() {
        // proxy.interceptors is a map: overlay entries override same-host
        // entries in the base, while non-overlapping keys union.
        let base = parse_recipe(
            r#"
[proxy.interceptors]
"example.com" = "/plugins/a.wasm"
"api.example.org" = "/plugins/b.wasm"
"#,
        );
        let overlay = parse_recipe(
            r#"
[proxy.interceptors]
"example.com" = "/plugins/a2.wasm"
"newhost.io" = "/plugins/c.wasm"
"#,
        );
        let merged = base.merge(overlay);
        let interceptors = &merged.proxy.interceptors;
        assert_eq!(
            interceptors.get("example.com").map(|p| p.as_path()),
            Some(std::path::Path::new("/plugins/a2.wasm")),
            "overlay must win for shared key",
        );
        assert_eq!(
            interceptors.get("api.example.org").map(|p| p.as_path()),
            Some(std::path::Path::new("/plugins/b.wasm")),
            "base-only key preserved",
        );
        assert_eq!(
            interceptors.get("newhost.io").map(|p| p.as_path()),
            Some(std::path::Path::new("/plugins/c.wasm")),
            "overlay-only key added",
        );
    }

    #[test]
    fn merge_proxy_limit_options_last_some_wins() {
        let base = parse_recipe(
            r#"
[proxy]
max_buffered_body_bytes = 1024
wasm_hook_timeout_ms = 100
"#,
        );
        // Empty overlay must NOT clear the values from base.
        let merged_empty_overlay = base.clone().merge(parse_recipe(""));
        assert_eq!(
            merged_empty_overlay.proxy.max_buffered_body_bytes,
            Some(1024)
        );
        assert_eq!(merged_empty_overlay.proxy.wasm_hook_timeout_ms, Some(100));

        // Overlay with its own values overrides.
        let merged_override = base.merge(parse_recipe(
            r#"
[proxy]
max_buffered_body_bytes = 8192
upstream_request_timeout_ms = 5000
"#,
        ));
        assert_eq!(merged_override.proxy.max_buffered_body_bytes, Some(8192));
        // wasm_hook_timeout_ms from base survives since overlay didn't set it.
        assert_eq!(merged_override.proxy.wasm_hook_timeout_ms, Some(100));
        assert_eq!(
            merged_override.proxy.upstream_request_timeout_ms,
            Some(5000)
        );
    }

    #[test]
    fn merge_case_different_domains_preserved_then_normalized_at_policy() {
        // The recipe merge layer treats domain entries as opaque strings
        // (union dedupes by exact bytes). The policy layer
        // (OutboundPolicy::from_config) is what folds case. This test
        // documents the contract so a future refactor doesn't
        // accidentally lowercase at merge time and break the round-trip
        // through serde for diagnostic output.
        let a = parse_recipe(
            r#"
[network]
allow_domains = ["Example.com"]
"#,
        );
        let b = parse_recipe(
            r#"
[network]
allow_domains = ["example.com"]
"#,
        );
        let merged = a.merge(b);
        // Both case variants present at the recipe layer.
        assert!(
            merged
                .network
                .allow_domains
                .iter()
                .any(|d| d == "Example.com"),
            "merged should still contain Example.com",
        );
        assert!(
            merged
                .network
                .allow_domains
                .iter()
                .any(|d| d == "example.com"),
            "merged should still contain example.com",
        );
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
allow_write = ["$_CANISTER_TEST_HOME2/.local/share/app"]
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
            config.filesystem.allow_write,
            vec![PathBuf::from("/home/bob/.local/share/app")]
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
