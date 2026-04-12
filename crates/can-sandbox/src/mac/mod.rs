//! Mandatory Access Control (MAC) abstraction layer.
//!
//! Linux distributions use different MAC systems to restrict unprivileged
//! processes. Ubuntu uses AppArmor, Fedora/RHEL use SELinux, and many
//! distributions (Arch, Void, Gentoo) use neither.
//!
//! This module provides a unified interface for:
//! - Detecting which MAC system is active
//! - Checking whether it restricts unprivileged user namespaces
//! - Installing/removing canister security policies
//! - Generating policy content for review
//!
//! See ADR-0004 for the design rationale.

pub mod apparmor;
pub mod selinux;

use std::path::PathBuf;

/// Status of the canister MAC policy on this system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyStatus {
    /// No MAC system restricts user namespaces — no policy needed.
    NotNeeded,
    /// Policy is not installed; filesystem isolation may be blocked.
    NotInstalled,
    /// Policy is installed and active.
    Installed { bin_path: String },
    /// Policy is installed but for a different binary path.
    WrongPath {
        installed_path: String,
        current_path: String,
    },
    /// Policy is installed but has stale content (e.g., template updated).
    Stale { bin_path: String },
}

/// Which MAC system is active on this kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MACSystem {
    AppArmor,
    SELinux,
}

impl std::fmt::Display for MACSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MACSystem::AppArmor => write!(f, "AppArmor"),
            MACSystem::SELinux => write!(f, "SELinux"),
        }
    }
}

/// Errors from MAC policy setup operations.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error(
        "permission denied — run with sudo:\n\n  \
         sudo can setup\n\n  \
         Or install manually:\n{manual_instructions}"
    )]
    NeedsSudo {
        policy_content: String,
        bin_path: String,
        manual_instructions: String,
    },

    #[error("failed to write policy to {path}: {source}")]
    WritePolicy {
        path: String,
        source: std::io::Error,
    },

    #[error("failed to run {cmd}: {source}")]
    Command { cmd: String, source: std::io::Error },

    #[error("{tool} failed:\n{stderr}")]
    ToolFailed { tool: String, stderr: String },

    #[error("canister MAC policy is not installed")]
    NotInstalled,

    #[error("{0}")]
    Other(String),
}

/// A MAC backend that can manage canister security policies.
pub trait MACBackend {
    /// Human-readable name of this MAC system.
    fn name(&self) -> &'static str;

    /// Which MAC system this backend represents.
    fn system(&self) -> MACSystem;

    /// Whether this MAC system is active on the running kernel.
    fn is_active(&self) -> bool;

    /// Whether this MAC system restricts unprivileged user namespaces.
    ///
    /// When true, canister needs a policy installed to use mount/pivot_root
    /// inside user namespaces.
    fn restricts_userns(&self) -> bool;

    /// Current status of the canister policy.
    fn policy_status(&self) -> PolicyStatus;

    /// Generate the policy content for the given binary path.
    ///
    /// Returns the primary policy file content (for display/review).
    fn generate_policy(&self, bin_path: &str) -> String;

    /// Install the canister policy.
    ///
    /// Must be run as root (typically via `sudo can setup`).
    fn install_policy(&self, bin_path: &str) -> Result<(), SetupError>;

    /// Remove the canister policy.
    ///
    /// Must be run as root.
    fn remove_policy(&self) -> Result<(), SetupError>;

    /// Path where the primary policy file is installed.
    fn policy_path(&self) -> &str;
}

/// Detect the active MAC system on this kernel.
///
/// Detection order:
/// 1. AppArmor: check `/sys/module/apparmor/parameters/enabled` == "Y"
/// 2. SELinux: check `/sys/fs/selinux/enforce` exists
/// 3. Neither: return `None`
///
/// It is theoretically possible to have both enabled (some distros stack LSMs),
/// but in practice one is primary. We check AppArmor first because Ubuntu is
/// the most common canister target.
pub fn detect_active() -> Option<MACSystem> {
    if apparmor::is_enabled() {
        return Some(MACSystem::AppArmor);
    }
    if selinux::is_enabled() {
        return Some(MACSystem::SELinux);
    }
    None
}

/// Get the MAC backend for the active system, if any.
///
/// Returns `None` on systems with no MAC (canister works without profiles
/// on these systems).
pub fn active_backend() -> Option<Box<dyn MACBackend>> {
    match detect_active() {
        Some(MACSystem::AppArmor) => Some(Box::new(apparmor::AppArmorBackend)),
        Some(MACSystem::SELinux) => Some(Box::new(selinux::SELinuxBackend)),
        None => None,
    }
}

/// Get the canonical path to the current `can` binary.
pub fn current_bin_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.display().to_string())
}

/// Resolve the `can` binary path: current exe, then PATH fallback.
pub fn resolve_bin_path() -> Option<String> {
    // First: current executable.
    if let Some(path) = current_bin_path() {
        return Some(path);
    }

    // Fallback: look up `can` in PATH.
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join("can");
            if candidate.exists() {
                if let Ok(canonical) = candidate.canonicalize() {
                    return Some(canonical.display().to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_bin_path_returns_some() {
        // In test context, this should return the test binary path.
        let path = current_bin_path();
        assert!(path.is_some());
    }

    #[test]
    fn mac_system_display() {
        assert_eq!(MACSystem::AppArmor.to_string(), "AppArmor");
        assert_eq!(MACSystem::SELinux.to_string(), "SELinux");
    }
}
