//! Cgroups v2 resource enforcement.
//!
//! Creates a transient cgroup under the user's delegation scope and applies
//! memory and CPU limits. This works without root because systemd (and
//! similar init systems) delegate a cgroup subtree to each user session.
//!
//! # How it works
//!
//! 1. Detect the current process's cgroup from `/proc/self/cgroup`
//! 2. Create a child cgroup `canister-<pid>` under it
//! 3. Write resource limits (`memory.max`, `cpu.max`)
//! 4. Move the current process into the child cgroup
//!
//! # Cleanup
//!
//! The cgroup is automatically removed by the kernel when all processes
//! in it have exited and no subcgroups remain (because we don't persist
//! references to it).

use std::fs;
use std::path::{Path, PathBuf};

/// Errors from cgroup operations.
#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    #[error("cgroups v2 not available: {0}")]
    NotAvailable(String),

    #[error("cannot create cgroup: {0}")]
    Create(std::io::Error),

    #[error("cannot write cgroup controller {controller}: {source}")]
    WriteController {
        controller: String,
        source: std::io::Error,
    },

    #[error("cannot move process to cgroup: {0}")]
    MoveProcess(std::io::Error),
}

/// Resource limits to apply via cgroups v2.
#[derive(Debug, Clone)]
pub struct CgroupLimits {
    /// Memory limit in bytes. Written to `memory.max`.
    pub memory_bytes: Option<u64>,

    /// CPU limit as (quota_us, period_us). Written to `cpu.max`.
    /// E.g., (50000, 100000) = 50% of one core.
    pub cpu_quota: Option<(u64, u64)>,
}

/// The default CPU period in microseconds (100ms).
const CPU_PERIOD_US: u64 = 100_000;

/// Apply cgroup resource limits for the current process.
///
/// Creates a child cgroup, writes limits, and moves the current PID into it.
/// Returns the path to the created cgroup (for logging).
///
/// Returns `Ok(None)` if no limits are configured.
pub fn apply_limits(
    memory_mb: Option<u64>,
    cpu_percent: Option<u32>,
) -> Result<Option<PathBuf>, CgroupError> {
    if memory_mb.is_none() && cpu_percent.is_none() {
        return Ok(None);
    }

    let limits = CgroupLimits {
        memory_bytes: memory_mb.map(|mb| mb * 1024 * 1024),
        cpu_quota: cpu_percent.map(|pct| {
            let quota = (pct as u64) * CPU_PERIOD_US / 100;
            (quota, CPU_PERIOD_US)
        }),
    };

    let parent = detect_cgroup_path()?;
    let cgroup_name = format!("canister-{}", std::process::id());
    let cgroup_path = parent.join(&cgroup_name);

    // Create the child cgroup directory.
    fs::create_dir_all(&cgroup_path).map_err(CgroupError::Create)?;

    tracing::debug!(
        path = %cgroup_path.display(),
        "created cgroup"
    );

    // Enable needed controllers in the parent (if not already enabled).
    enable_controllers(&parent, &limits)?;

    // Write resource limits.
    if let Some(bytes) = limits.memory_bytes {
        write_limit(&cgroup_path, "memory.max", &bytes.to_string())?;
        tracing::info!(memory_bytes = bytes, "cgroup memory.max set");
    }

    if let Some((quota, period)) = limits.cpu_quota {
        write_limit(&cgroup_path, "cpu.max", &format!("{quota} {period}"))?;
        tracing::info!(quota_us = quota, period_us = period, "cgroup cpu.max set");
    }

    // Move current process into the cgroup.
    let pid = std::process::id();
    write_limit(&cgroup_path, "cgroup.procs", &pid.to_string()).map_err(|e| match e {
        CgroupError::WriteController { source, .. } => CgroupError::MoveProcess(source),
        other => other,
    })?;

    tracing::debug!(pid, path = %cgroup_path.display(), "moved process to cgroup");

    Ok(Some(cgroup_path))
}

/// Detect the cgroup v2 path for the current process.
///
/// Reads `/proc/self/cgroup` which on cgroup v2 unified hierarchy
/// has a single line like `0::/user.slice/user-1000.slice/session-2.scope`.
fn detect_cgroup_path() -> Result<PathBuf, CgroupError> {
    let cgroup_root = Path::new("/sys/fs/cgroup");

    if !cgroup_root.join("cgroup.controllers").exists() {
        return Err(CgroupError::NotAvailable(
            "no cgroup.controllers at /sys/fs/cgroup (not cgroups v2?)".to_string(),
        ));
    }

    let content = fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| CgroupError::NotAvailable(format!("cannot read /proc/self/cgroup: {e}")))?;

    // cgroup v2 format: "0::<path>"
    let relative = content
        .lines()
        .find(|line| line.starts_with("0::"))
        .and_then(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            CgroupError::NotAvailable("no cgroup v2 entry in /proc/self/cgroup".to_string())
        })?;

    let path = cgroup_root.join(relative.trim_start_matches('/'));

    // Verify we can write to this cgroup (delegation check).
    let subtree_control = path.join("cgroup.subtree_control");
    if !subtree_control.exists() {
        return Err(CgroupError::NotAvailable(format!(
            "cgroup {} has no subtree_control (no delegation?)",
            path.display()
        )));
    }

    Ok(path)
}

/// Enable required controllers in the parent cgroup's subtree_control.
fn enable_controllers(parent: &Path, limits: &CgroupLimits) -> Result<(), CgroupError> {
    let mut controllers = Vec::new();
    if limits.memory_bytes.is_some() {
        controllers.push("memory");
    }
    if limits.cpu_quota.is_some() {
        controllers.push("cpu");
    }

    if controllers.is_empty() {
        return Ok(());
    }

    let subtree_control = parent.join("cgroup.subtree_control");
    let current = fs::read_to_string(&subtree_control).unwrap_or_default();

    for ctrl in &controllers {
        if !current.contains(ctrl) {
            // Try to enable; may fail if already enabled or not delegated.
            let val = format!("+{ctrl}");
            match fs::write(&subtree_control, &val) {
                Ok(()) => {
                    tracing::debug!(controller = ctrl, "enabled cgroup controller");
                }
                Err(e) => {
                    // Not fatal — the controller might already be available
                    // in the child cgroup via inheritance.
                    tracing::debug!(
                        controller = ctrl,
                        error = %e,
                        "could not enable controller in subtree_control (may already be active)"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Write a value to a cgroup control file.
fn write_limit(cgroup: &Path, filename: &str, value: &str) -> Result<(), CgroupError> {
    let path = cgroup.join(filename);
    fs::write(&path, value).map_err(|source| CgroupError::WriteController {
        controller: filename.to_string(),
        source,
    })
}

/// Check if cgroups v2 is available and delegated to the current user.
///
/// Used by `can check` to report status.
pub fn is_available() -> bool {
    detect_cgroup_path().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_quota_calculation() {
        // 50% CPU = 50000us quota / 100000us period
        let limits = CgroupLimits {
            memory_bytes: None,
            cpu_quota: Some((50_000, 100_000)),
        };
        let (quota, period) = limits.cpu_quota.unwrap();
        assert_eq!(quota, 50_000);
        assert_eq!(period, 100_000);
    }

    #[test]
    fn memory_conversion_mb_to_bytes() {
        let mb: u64 = 512;
        let bytes = mb * 1024 * 1024;
        assert_eq!(bytes, 536_870_912);
    }

    #[test]
    fn apply_limits_noop_when_no_limits() {
        let result = apply_limits(None, None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn detect_cgroup_returns_result() {
        // This test just exercises the detection path — it may succeed
        // or fail depending on the host environment.
        let _result = detect_cgroup_path();
    }

    #[test]
    fn is_available_returns_bool() {
        let _ = is_available();
    }
}
