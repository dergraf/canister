use std::path::Path;

use crate::setup;

/// Detected kernel capabilities for sandboxing.
#[derive(Debug, Clone)]
pub struct KernelCapabilities {
    /// Can create unprivileged user namespaces.
    pub user_namespaces: bool,

    /// PID namespaces are available.
    pub pid_namespaces: bool,

    /// Mount namespaces are available (needs user namespace or root).
    pub mount_namespaces: bool,

    /// Network namespaces are available.
    pub network_namespaces: bool,

    /// Cgroups v2 is available and writable.
    pub cgroups_v2: bool,

    /// OverlayFS is available.
    pub overlayfs: bool,

    /// Seccomp BPF is available.
    pub seccomp_bpf: bool,

    /// AppArmor restricts unprivileged user namespaces.
    /// When true, mount operations inside user namespaces are blocked
    /// unless the canister AppArmor profile is installed.
    pub apparmor_restricts_userns: bool,

    /// Whether the canister AppArmor profile is installed and active.
    pub canister_profile_installed: bool,

    /// Kernel version string.
    pub kernel_version: String,
}

impl KernelCapabilities {
    /// Detect available kernel capabilities.
    pub fn detect() -> Self {
        let apparmor_restricts = setup::apparmor_restricts_userns();
        let profile_status = setup::detect_profile_status();
        let profile_installed = matches!(
            profile_status,
            setup::ProfileStatus::NotNeeded
                | setup::ProfileStatus::Installed { .. }
                | setup::ProfileStatus::Stale { .. }
        );

        // Mount namespaces work if AppArmor doesn't restrict, or if our profile is installed.
        let mount_ns = !apparmor_restricts || profile_installed;

        Self {
            user_namespaces: check_user_namespaces(),
            pid_namespaces: check_pid_namespaces(),
            mount_namespaces: mount_ns,
            network_namespaces: check_network_namespaces(),
            cgroups_v2: check_cgroups_v2(),
            overlayfs: check_overlayfs(),
            seccomp_bpf: check_seccomp(),
            apparmor_restricts_userns: apparmor_restricts,
            canister_profile_installed: profile_installed,
            kernel_version: get_kernel_version(),
        }
    }

    /// Print a human-readable summary of detected capabilities.
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Kernel: {}", self.kernel_version));
        lines.push(format!(
            "  User namespaces:   {}",
            status(self.user_namespaces)
        ));
        lines.push(format!(
            "  PID namespaces:    {}",
            status(self.pid_namespaces)
        ));
        lines.push(format!("  Mount namespaces:  {}", fmt_mount_ns(self)));
        lines.push(format!(
            "  Network namespaces: {}",
            status(self.network_namespaces)
        ));
        lines.push(format!("  Cgroups v2:        {}", status(self.cgroups_v2)));
        lines.push(format!("  OverlayFS:         {}", status(self.overlayfs)));
        lines.push(format!("  Seccomp BPF:       {}", status(self.seccomp_bpf)));

        lines.join("\n")
    }

    /// Returns true if the minimum requirements for sandboxing are met.
    pub fn meets_minimum(&self) -> bool {
        self.user_namespaces && self.pid_namespaces
    }

    /// Returns true if full filesystem isolation (pivot_root) can be used.
    pub fn can_pivot_root(&self) -> bool {
        self.mount_namespaces
    }
}

fn status(available: bool) -> &'static str {
    if available {
        "available"
    } else {
        "NOT available"
    }
}

fn fmt_mount_ns(caps: &KernelCapabilities) -> &'static str {
    if caps.apparmor_restricts_userns && !caps.canister_profile_installed {
        "BLOCKED by AppArmor (run `sudo can setup` to fix)"
    } else if caps.mount_namespaces {
        "available"
    } else {
        "NOT available"
    }
}

fn check_user_namespaces() -> bool {
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        return content.trim() == "1";
    }
    if let Ok(content) = std::fs::read_to_string("/proc/sys/user/max_user_namespaces") {
        if let Ok(max) = content.trim().parse::<u64>() {
            return max > 0;
        }
    }
    false
}

fn check_pid_namespaces() -> bool {
    Path::new("/proc/sys/kernel/pid_max").exists()
}

fn check_network_namespaces() -> bool {
    check_user_namespaces()
}

fn check_cgroups_v2() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

fn check_overlayfs() -> bool {
    if let Ok(content) = std::fs::read_to_string("/proc/filesystems") {
        return content.contains("overlay");
    }
    false
}

fn check_seccomp() -> bool {
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail") {
        return content.contains("log");
    }
    if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
        return content.contains("Seccomp:");
    }
    false
}

fn get_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string()
}
