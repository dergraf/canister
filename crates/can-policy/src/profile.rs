use serde::Deserialize;

/// A seccomp profile defines which syscalls are allowed for a given workload type.
///
/// In Phase 1, this is a placeholder. The actual BPF filter generation
/// comes in Phase 4.
#[derive(Debug, Clone, Deserialize)]
pub struct SeccompProfile {
    /// Human-readable name.
    pub name: String,

    /// Description of what this profile is designed for.
    pub description: String,

    /// Syscalls explicitly allowed (Phase 4: used to build BPF filter).
    #[serde(default)]
    pub allow_syscalls: Vec<String>,

    /// Syscalls explicitly blocked.
    #[serde(default)]
    pub deny_syscalls: Vec<String>,
}

impl SeccompProfile {
    /// Load a built-in profile by name.
    ///
    /// Returns `None` if the profile name is unknown.
    pub fn builtin(name: &str) -> Option<Self> {
        match name {
            "generic" => Some(Self {
                name: "generic".to_string(),
                description: "Generic profile for arbitrary binaries. Permissive.".to_string(),
                allow_syscalls: Vec::new(),
                deny_syscalls: vec![
                    "reboot".to_string(),
                    "kexec_load".to_string(),
                    "mount".to_string(),
                    "umount2".to_string(),
                    "pivot_root".to_string(),
                    "swapon".to_string(),
                    "swapoff".to_string(),
                ],
            }),
            "python" => Some(Self {
                name: "python".to_string(),
                description: "Profile for Python scripts.".to_string(),
                allow_syscalls: Vec::new(),
                deny_syscalls: vec![
                    "reboot".to_string(),
                    "kexec_load".to_string(),
                    "mount".to_string(),
                    "umount2".to_string(),
                    "pivot_root".to_string(),
                    "ptrace".to_string(),
                ],
            }),
            "node" => Some(Self {
                name: "node".to_string(),
                description: "Profile for Node.js scripts.".to_string(),
                allow_syscalls: Vec::new(),
                deny_syscalls: vec![
                    "reboot".to_string(),
                    "kexec_load".to_string(),
                    "mount".to_string(),
                    "umount2".to_string(),
                    "pivot_root".to_string(),
                    "ptrace".to_string(),
                ],
            }),
            _ => None,
        }
    }

    /// List all built-in profile names.
    pub fn builtin_names() -> &'static [&'static str] {
        &["generic", "python", "node"]
    }
}
