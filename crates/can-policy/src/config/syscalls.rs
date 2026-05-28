use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use super::merge::union_vecs;

/// Syscalls that materially widen the kernel attack surface or enable
/// sandbox-escape primitives. They are rejected from `[syscalls] allow_extra`
/// and must be declared in `[unsafe] extra_syscalls` so the cost is explicit.
///
/// Curated, not exhaustive — the audit question is "could allowing this let
/// sandboxed code inspect/inject other processes, load kernel code, remount
/// the filesystem, manipulate namespaces, or open a known exploit surface?"
pub const DANGEROUS_SYSCALLS: &[&str] = &[
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "bpf",
    "mount",
    "umount2",
    "move_mount",
    "open_tree",
    "fsopen",
    "fsconfig",
    "fsmount",
    "pivot_root",
    "chroot",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "personality",
    "seccomp",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "perf_event_open",
    "userfaultfd",
    "add_key",
    "keyctl",
    "request_key",
    "swapon",
    "swapoff",
    "reboot",
];

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
    /// Seccomp enforcement mode (runtime-resolved). `AllowList`
    /// (default-deny) is the only mode a recipe can ask for implicitly;
    /// flipping to `DenyList` (default-**allow**) inverts the security
    /// posture, so it is authored as `[unsafe] seccomp_default_allow`.
    /// `#[serde(skip)]` makes `[syscalls] seccomp_mode` a hard error.
    #[serde(skip)]
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

    /// Validate that absolute and relative fields are not mixed, and that
    /// no dangerous syscall is smuggled in via `allow_extra` (those belong
    /// in `[unsafe] extra_syscalls`).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.is_baseline() && self.is_override() {
            return Err(ConfigError::Validation(
                "[syscalls] cannot mix absolute (allow/deny) and relative (allow_extra/deny_extra) fields. \
                 Use allow/deny only in default.toml; use allow_extra/deny_extra in regular recipes."
                    .to_string(),
            ));
        }
        let dangerous: Vec<&str> = self
            .allow_extra
            .iter()
            .filter(|s| DANGEROUS_SYSCALLS.contains(&s.as_str()))
            .map(|s| s.as_str())
            .collect();
        if !dangerous.is_empty() {
            return Err(ConfigError::Validation(format!(
                "[syscalls] allow_extra contains isolation-weakening syscalls {dangerous:?}; \
                 declare these under [unsafe] extra_syscalls instead."
            )));
        }
        Ok(())
    }

    pub fn merge(self, overlay: Self) -> Self {
        Self {
            seccomp_mode: overlay.seccomp_mode.or(self.seccomp_mode),
            notifier: overlay.notifier.or(self.notifier),
            allow: union_vecs(self.allow, overlay.allow),
            deny: union_vecs(self.deny, overlay.deny),
            allow_extra: union_vecs(self.allow_extra, overlay.allow_extra),
            deny_extra: union_vecs(self.deny_extra, overlay.deny_extra),
        }
    }
}
