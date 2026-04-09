use std::path::PathBuf;

use serde::Deserialize;

use crate::config::{ConfigError, RecipeFile, SyscallConfig};

/// The default baseline TOML, embedded at compile time.
///
/// This is the fallback when no external `default.toml` is found in
/// the recipe search path. The file lives at `recipes/default.toml`
/// in the source tree.
const EMBEDDED_DEFAULT: &str = include_str!("../../../recipes/default.toml");

/// The base recipe TOML, embedded at compile time.
///
/// This provides essential OS bind mounts (binaries, libraries, etc.)
/// that every sandbox needs. Replaces the hardcoded ESSENTIAL_BIND_MOUNTS
/// for auditability and customization.
const EMBEDDED_BASE: &str = include_str!("../../../recipes/base.toml");

/// A seccomp profile defines which syscalls are allowed or denied.
///
/// There is one canonical baseline defined in `recipes/default.toml`.
/// At runtime, the baseline is resolved from the recipe search path
/// (project-local → per-user → system-wide) with the embedded copy
/// as a fallback.
///
/// Supports two enforcement modes:
/// - **Allow-list** (default deny): only syscalls in `allow_syscalls` are
///   permitted. Everything else is blocked. Recommended for production/CI.
/// - **Deny-list** (default allow): only syscalls in `deny_syscalls` are
///   blocked. Everything else is permitted. More permissive, useful for
///   compatibility when the workload's syscall set is unknown.
///
/// The mode is selected via `[syscalls] seccomp_mode` in the recipe.
#[derive(Debug, Clone, Deserialize)]
pub struct SeccompProfile {
    /// Human-readable name.
    pub name: String,

    /// Description of what this profile is designed for.
    pub description: String,

    /// Syscalls explicitly allowed (used in allow-list mode).
    #[serde(default)]
    pub allow_syscalls: Vec<String>,

    /// Syscalls explicitly blocked (used in deny-list mode).
    #[serde(default)]
    pub deny_syscalls: Vec<String>,
}

/// Where the baseline was loaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineSource {
    /// Loaded from an external file on the recipe search path.
    External(PathBuf),
    /// Using the copy embedded in the binary.
    Embedded,
}

impl std::fmt::Display for BaselineSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::External(path) => write!(f, "{}", path.display()),
            Self::Embedded => write!(f, "(embedded)"),
        }
    }
}

/// Result of resolving the default baseline.
#[derive(Debug, Clone)]
pub struct ResolvedBaseline {
    /// The seccomp profile built from the baseline.
    pub profile: SeccompProfile,
    /// Where the baseline was loaded from.
    pub source: BaselineSource,
}

impl SeccompProfile {
    /// Resolve and return the default baseline.
    ///
    /// Search order:
    /// 1. `./recipes/default.toml` (project-local)
    /// 2. `$XDG_CONFIG_HOME/canister/recipes/default.toml` (per-user)
    /// 3. `/etc/canister/recipes/default.toml` (system-wide)
    /// 4. Embedded fallback (compiled into the binary)
    ///
    /// Returns the profile and its source for diagnostics.
    pub fn resolve_baseline() -> Result<ResolvedBaseline, ConfigError> {
        // Try external files first.
        for dir in baseline_search_dirs() {
            let path = dir.join("default.toml");
            if path.is_file() {
                let recipe = RecipeFile::from_file(&path)?;
                let config = recipe.into_sandbox_config()?;
                let profile = Self::from_baseline_config(&config.syscalls)?;
                return Ok(ResolvedBaseline {
                    profile,
                    source: BaselineSource::External(path),
                });
            }
        }

        // Fall back to the embedded copy.
        Self::from_embedded()
    }

    /// Build a baseline from the embedded default.toml.
    fn from_embedded() -> Result<ResolvedBaseline, ConfigError> {
        let recipe = RecipeFile::parse(EMBEDDED_DEFAULT)?;
        let config = recipe.into_sandbox_config()?;
        let profile = Self::from_baseline_config(&config.syscalls)?;
        Ok(ResolvedBaseline {
            profile,
            source: BaselineSource::Embedded,
        })
    }

    /// Build a `SeccompProfile` from a baseline `SyscallConfig` (one that
    /// uses absolute `allow`/`deny` fields).
    fn from_baseline_config(syscalls: &SyscallConfig) -> Result<Self, ConfigError> {
        if !syscalls.is_baseline() {
            return Err(ConfigError::Validation(
                "default.toml must use absolute [syscalls] allow/deny fields".to_string(),
            ));
        }
        Ok(Self {
            name: "default".to_string(),
            description: "Default baseline — common syscalls for any Linux process. \
                          Blocks dangerous kernel operations and namespace escapes."
                .to_string(),
            allow_syscalls: syscalls.allow.clone(),
            deny_syscalls: syscalls.deny.clone(),
        })
    }

    /// Build a profile directly from absolute `allow`/`deny` fields.
    ///
    /// Used when a `SyscallConfig` with `is_baseline() == true` is passed
    /// directly (e.g., when `--recipe default.toml` is used explicitly).
    pub fn from_absolute(syscalls: &SyscallConfig) -> Self {
        Self {
            name: "custom-baseline".to_string(),
            description: "Baseline from absolute allow/deny fields".to_string(),
            allow_syscalls: syscalls.allow.clone(),
            deny_syscalls: syscalls.deny.clone(),
        }
    }

    /// Return the single built-in "default" baseline.
    ///
    /// Convenience wrapper that resolves from the embedded copy.
    /// Panics if the embedded default.toml is malformed (compile-time
    /// guarantee — this should never happen).
    pub fn default_baseline() -> Self {
        Self::from_embedded()
            .expect("embedded default.toml is malformed")
            .profile
    }

    /// Apply recipe-level syscall overrides on top of the baseline.
    ///
    /// - `allow_extra`: syscalls added to the allow list
    /// - `deny_extra`: syscalls added to the deny list and removed from allow list
    pub fn apply_overrides(&mut self, allow_extra: &[String], deny_extra: &[String]) {
        // Add extra allows (deduplicated).
        for syscall in allow_extra {
            if !self.allow_syscalls.contains(syscall) {
                self.allow_syscalls.push(syscall.clone());
            }
        }

        // Add extra denies and remove them from allow list.
        for syscall in deny_extra {
            self.allow_syscalls.retain(|s| s != syscall);
            if !self.deny_syscalls.contains(syscall) {
                self.deny_syscalls.push(syscall.clone());
            }
        }
    }
}

/// Resolve the base recipe (essential OS mounts).
///
/// Search order (same as `default.toml`):
/// 1. `./recipes/base.toml` (project-local)
/// 2. `$XDG_CONFIG_HOME/canister/recipes/base.toml` (per-user)
/// 3. `/etc/canister/recipes/base.toml` (system-wide)
/// 4. Embedded fallback (compiled into the binary)
///
/// Returns the parsed `RecipeFile` for merging into the composition stack.
pub fn resolve_base() -> Result<RecipeFile, ConfigError> {
    for dir in baseline_search_dirs() {
        let path = dir.join("base.toml");
        if path.is_file() {
            tracing::debug!(path = %path.display(), "loading external base.toml");
            return RecipeFile::from_file(&path);
        }
    }

    tracing::debug!("using embedded base.toml");
    RecipeFile::parse(EMBEDDED_BASE)
}

/// Directories searched for the default baseline, in priority order.
///
/// This is also used by `can-cli` for recipe discovery.
pub fn baseline_search_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("recipes")];

    // XDG_CONFIG_HOME, defaulting to ~/.config
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        dirs.push(PathBuf::from(xdg).join("canister/recipes"));
    } else if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join(".config/canister/recipes"));
    }

    dirs.push(PathBuf::from("/etc/canister/recipes"));
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_default_parses() {
        let resolved = SeccompProfile::from_embedded().unwrap();
        assert_eq!(resolved.source, BaselineSource::Embedded);
        assert!(
            resolved.profile.allow_syscalls.len() > 100,
            "expected >100 allowed syscalls, got {}",
            resolved.profile.allow_syscalls.len()
        );
        assert!(
            resolved.profile.deny_syscalls.len() >= 14,
            "expected >=14 denied syscalls, got {}",
            resolved.profile.deny_syscalls.len()
        );
    }

    #[test]
    fn default_baseline_convenience() {
        let profile = SeccompProfile::default_baseline();
        assert_eq!(profile.name, "default");
        assert!(profile.allow_syscalls.len() > 100);
        assert!(profile.deny_syscalls.len() >= 14);
    }

    #[test]
    fn apply_overrides_adds_allow() {
        let mut profile = SeccompProfile::default_baseline();
        let base_count = profile.allow_syscalls.len();
        profile.apply_overrides(&["ptrace".to_string()], &[]);
        assert_eq!(profile.allow_syscalls.len(), base_count + 1);
        assert!(profile.allow_syscalls.contains(&"ptrace".to_string()));
    }

    #[test]
    fn apply_overrides_adds_deny_and_removes_from_allow() {
        let mut profile = SeccompProfile::default_baseline();
        assert!(profile.allow_syscalls.contains(&"read".to_string()));
        profile.apply_overrides(&[], &["read".to_string()]);
        assert!(!profile.allow_syscalls.contains(&"read".to_string()));
        assert!(profile.deny_syscalls.contains(&"read".to_string()));
    }

    #[test]
    fn apply_overrides_deduplicates_allow() {
        let mut profile = SeccompProfile::default_baseline();
        let base_count = profile.allow_syscalls.len();
        profile.apply_overrides(&["read".to_string()], &[]);
        assert_eq!(profile.allow_syscalls.len(), base_count);
    }

    #[test]
    fn apply_overrides_deduplicates_deny() {
        let mut profile = SeccompProfile::default_baseline();
        let base_deny_count = profile.deny_syscalls.len();
        profile.apply_overrides(&[], &["reboot".to_string()]);
        assert_eq!(profile.deny_syscalls.len(), base_deny_count);
    }

    #[test]
    fn no_overlap_between_allow_and_deny() {
        let profile = SeccompProfile::default_baseline();
        for syscall in &profile.allow_syscalls {
            assert!(
                !profile.deny_syscalls.contains(syscall),
                "syscall '{syscall}' appears in both allow and deny lists"
            );
        }
    }

    #[test]
    fn baseline_source_display() {
        assert_eq!(BaselineSource::Embedded.to_string(), "(embedded)");
        assert_eq!(
            BaselineSource::External(PathBuf::from("/etc/canister/recipes/default.toml"))
                .to_string(),
            "/etc/canister/recipes/default.toml"
        );
    }

    #[test]
    fn resolve_baseline_returns_embedded_when_no_external() {
        // In test environment, there may or may not be a ./recipes/default.toml.
        // We just verify it doesn't error.
        let resolved = SeccompProfile::resolve_baseline().unwrap();
        assert!(resolved.profile.allow_syscalls.len() > 100);
    }

    #[test]
    fn embedded_base_parses() {
        let base = resolve_base().unwrap();
        assert_eq!(base.display_name("base"), "base");
        // base.toml should have essential paths in filesystem.allow
        assert!(
            !base.filesystem.allow.is_empty(),
            "base.toml should have filesystem.allow entries"
        );
        // Verify key paths are present
        let paths: Vec<String> = base
            .filesystem
            .allow
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert!(
            paths.contains(&"/bin".to_string()),
            "base should include /bin"
        );
        assert!(
            paths.contains(&"/usr/lib".to_string()),
            "base should include /usr/lib"
        );
        assert!(
            paths.contains(&"/etc/resolv.conf".to_string()),
            "base should include /etc/resolv.conf"
        );
    }
}
