use std::path::Path;

/// Detected kernel capabilities for sandboxing.
#[derive(Debug)]
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

    /// Kernel version string.
    pub kernel_version: String,
}

impl KernelCapabilities {
    /// Detect available kernel capabilities.
    pub fn detect() -> Self {
        Self {
            user_namespaces: check_user_namespaces(),
            pid_namespaces: check_pid_namespaces(),
            mount_namespaces: true, // available if user ns works
            network_namespaces: check_network_namespaces(),
            cgroups_v2: check_cgroups_v2(),
            overlayfs: check_overlayfs(),
            seccomp_bpf: check_seccomp(),
            kernel_version: get_kernel_version(),
        }
    }

    /// Print a human-readable summary of detected capabilities.
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Kernel: {}", self.kernel_version));
        lines.push(format!(
            "  User namespaces:    {}",
            status(self.user_namespaces)
        ));
        lines.push(format!(
            "  PID namespaces:     {}",
            status(self.pid_namespaces)
        ));
        lines.push(format!(
            "  Mount namespaces:   {}",
            status(self.mount_namespaces)
        ));
        lines.push(format!(
            "  Network namespaces: {}",
            status(self.network_namespaces)
        ));
        lines.push(format!("  Cgroups v2:         {}", status(self.cgroups_v2)));
        lines.push(format!("  OverlayFS:          {}", status(self.overlayfs)));
        lines.push(format!(
            "  Seccomp BPF:        {}",
            status(self.seccomp_bpf)
        ));
        lines.join("\n")
    }

    /// Returns true if the minimum requirements for sandboxing are met.
    pub fn meets_minimum(&self) -> bool {
        self.user_namespaces && self.pid_namespaces
    }
}

fn status(available: bool) -> &'static str {
    if available {
        "available"
    } else {
        "NOT available"
    }
}

fn check_user_namespaces() -> bool {
    // Check if unprivileged user namespaces are enabled.
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        return content.trim() == "1";
    }
    // If the file doesn't exist, user namespaces may still be available
    // (newer kernels don't have this sysctl). Check by trying to read max_user_namespaces.
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
    // Network namespaces require user namespace support.
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
    // Fallback: check /proc/self/status for Seccomp field
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
