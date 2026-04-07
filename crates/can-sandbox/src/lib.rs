pub mod capabilities;
pub mod namespace;
pub mod overlay;
pub mod process;
pub mod seccomp;
pub mod setup;

use std::ffi::CString;
use std::path::Path;

use can_policy::SandboxConfig;

/// Errors from sandbox operations.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("namespace setup failed: {0}")]
    Namespace(#[from] namespace::NamespaceError),

    #[error("failed to exec target command: {0}")]
    Exec(#[from] nix::Error),

    #[error("invalid command path: {0}")]
    InvalidCommand(String),

    #[error("capability detection failed: {0}")]
    Capability(String),

    #[error("network setup failed: {0}")]
    Network(#[from] can_net::NetError),

    #[error("sandbox child process failed with status: {0}")]
    ChildFailed(i32),

    #[error("process control failed: {0}")]
    Process(#[from] process::ProcessError),
}

/// Options for launching a sandboxed process.
#[derive(Debug)]
pub struct SandboxOpts {
    /// The command to execute inside the sandbox.
    pub command: String,

    /// Arguments to pass to the command.
    pub args: Vec<String>,

    /// Sandbox configuration (policy).
    pub config: SandboxConfig,

    /// Run in monitor mode (log but don't enforce).
    pub monitor: bool,
}

/// Run a command inside the sandbox.
///
/// This is the main entry point. It:
/// 1. Creates namespaces (PID, user, mount, optionally network)
/// 2. Applies policy (filesystem, network, seccomp) — Phase 2+
/// 3. Executes the target command
///
/// Returns the exit code of the sandboxed process.
pub fn run(opts: &SandboxOpts) -> Result<i32, SandboxError> {
    tracing::info!(
        command = %opts.command,
        args = ?opts.args,
        monitor = opts.monitor,
        "starting sandbox"
    );

    // Fork into a new set of namespaces.
    let exit_code = namespace::spawn_sandboxed(opts)?;

    tracing::info!(exit_code, "sandbox exited");
    Ok(exit_code)
}

/// Convert a command string to a CString for execve.
pub(crate) fn to_cstring(s: &str) -> Result<CString, SandboxError> {
    CString::new(s.as_bytes()).map_err(|_| SandboxError::InvalidCommand(s.to_string()))
}

/// Resolve a command to its full path using PATH lookup.
///
/// Returns the **canonicalized** path with all symlinks resolved. This is
/// critical for sandboxing: the kernel follows symlinks during execve, and
/// every intermediate target must exist inside the sandbox. By canonicalizing
/// upfront we avoid having to replicate multi-hop symlink chains (common
/// with Nix/home-manager) inside the isolated filesystem.
pub(crate) fn resolve_command(cmd: &str) -> Result<std::path::PathBuf, SandboxError> {
    let found = if Path::new(cmd).is_absolute() {
        std::path::PathBuf::from(cmd)
    } else {
        // Search PATH
        let mut result = None;
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in path_var.split(':') {
                let candidate = Path::new(dir).join(cmd);
                if candidate.exists() {
                    result = Some(candidate);
                    break;
                }
            }
        }
        result.ok_or_else(|| SandboxError::InvalidCommand(format!("command not found: {cmd}")))?
    };

    // Canonicalize to resolve all symlinks. This converts paths like
    // /home/user/.nix-profile/bin/iex → /nix/store/<hash>-elixir/bin/iex
    // so the sandbox only needs the final target mounted.
    found.canonicalize().map_err(|e| {
        SandboxError::InvalidCommand(format!("cannot resolve {}: {e}", found.display()))
    })
}

/// Detect the package-manager prefix that should be bind-mounted for a
/// command to work inside the sandbox.
///
/// Rather than trying to resolve the full transitive dependency graph
/// (shared libraries, script deps, etc.), we mount the **entire prefix
/// tree** that the command lives under. This is generic across package
/// managers (Nix, Homebrew, Guix, Snap, etc.) and avoids chasing an
/// unbounded closure.
///
/// Security is enforced at the execution layer (`allow_execve`), not
/// the filesystem layer — visibility != permission.
///
/// Returns `None` if the command is under a path already covered by
/// the essential bind mounts (`/usr/bin`, `/lib`, etc.).
///
/// # Examples
///
/// | Command path                                     | Detected prefix     |
/// |--------------------------------------------------|---------------------|
/// | `/nix/store/<hash>-elixir/bin/iex`               | `/nix/store`        |
/// | `/gnu/store/<hash>-guile/bin/guile`               | `/gnu/store`        |
/// | `/opt/homebrew/bin/python3`                       | `/opt/homebrew`     |
/// | `/snap/core/current/usr/bin/hello`                | `/snap`             |
/// | `/home/user/.local/bin/tool`                      | `/home/user/.local` |
/// | `/usr/bin/python3`                                | `None` (essential)  |
pub(crate) fn detect_command_prefix(command_path: &Path) -> Option<std::path::PathBuf> {
    // If the command is under an essential path, no extra mount needed.
    if is_essential_path(command_path) {
        return None;
    }

    let s = command_path.to_string_lossy();

    // Known content-addressed / append-only stores: mount the store root,
    // not individual entries. The entire store is needed because binaries
    // inside reference sibling store entries freely.
    //
    // /nix/store/<hash>-name/... → /nix/store
    // /gnu/store/<hash>-name/... → /gnu/store
    for store_root in &["/nix/store/", "/gnu/store/"] {
        if s.starts_with(store_root) {
            return Some(std::path::PathBuf::from(store_root.trim_end_matches('/')));
        }
    }

    // Known package manager prefixes: mount the prefix root.
    //
    // /opt/homebrew/Cellar/python/3.12/bin/python → /opt/homebrew
    // /snap/core22/current/usr/bin/hello           → /snap
    // /var/lib/flatpak/app/org.foo/...             → /var/lib/flatpak
    for (prefix, depth) in &[
        ("/opt/homebrew/", 3),    // /opt/homebrew
        ("/snap/", 2),            // /snap
        ("/var/lib/flatpak/", 4), // /var/lib/flatpak
    ] {
        if s.starts_with(prefix) {
            return Some(take_components(command_path, *depth));
        }
    }

    // Paths under /home or similar: mount enough to cover the install.
    // /home/user/.local/bin/tool → /home/user/.local
    // /home/user/.cargo/bin/rg  → /home/user/.cargo
    if s.starts_with("/home/") {
        // Find the dotdir or known subdir pattern.
        let components: Vec<_> = command_path.components().collect();
        // /home/<user>/.<something>/... → mount /home/<user>/.<something>
        // /home/<user>/bin/...          → mount /home/<user>
        for (i, comp) in components.iter().enumerate() {
            if let std::path::Component::Normal(name) = comp {
                let name = name.to_string_lossy();
                if name.starts_with('.') && i >= 3 {
                    // Mount up to and including the dotdir.
                    return Some(take_components(command_path, i + 1));
                }
            }
        }
        // Fallback: /home/<user>
        return Some(take_components(command_path, 3));
    }

    // Generic fallback: mount the first two real path components.
    // /<category>/<name>/... → /<category>/<name>
    Some(take_components(command_path, 3))
}

/// Paths that are already covered by essential bind mounts.
const ESSENTIAL_PREFIXES: &[&str] = &[
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/share",
    "/etc",
    "/proc",
    "/dev",
    "/tmp",
];

/// Check whether a path is already covered by essential bind mounts.
///
/// Uses `Path::starts_with` for component-wise matching, so `/binary-thing`
/// does NOT match `/bin`.
fn is_essential_path(path: &Path) -> bool {
    ESSENTIAL_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Take the first `n` components of a path (including the root `/` component).
///
/// For example, `take_components("/nix/store/hash-name/bin/iex", 3)` returns
/// `/nix/store` because the components are: [`/`, `nix`, `store`, ...].
fn take_components(path: &Path, n: usize) -> std::path::PathBuf {
    let mut result = std::path::PathBuf::new();
    for (i, component) in path.components().enumerate() {
        if i >= n {
            break;
        }
        result.push(component);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // --- is_essential_path ---

    #[test]
    fn essential_path_usr_bin() {
        assert!(is_essential_path(Path::new("/usr/bin/python3")));
    }

    #[test]
    fn essential_path_bin() {
        assert!(is_essential_path(Path::new("/bin/ls")));
    }

    #[test]
    fn essential_path_etc() {
        assert!(is_essential_path(Path::new("/etc/resolv.conf")));
    }

    #[test]
    fn essential_path_proc() {
        assert!(is_essential_path(Path::new("/proc/self/status")));
    }

    #[test]
    fn essential_path_tmp() {
        assert!(is_essential_path(Path::new("/tmp/foo")));
    }

    #[test]
    fn not_essential_nix_store() {
        assert!(!is_essential_path(Path::new(
            "/nix/store/abc-elixir/bin/iex"
        )));
    }

    #[test]
    fn not_essential_opt_homebrew() {
        assert!(!is_essential_path(Path::new("/opt/homebrew/bin/python3")));
    }

    #[test]
    fn not_essential_string_prefix_bug() {
        // "/binary-thing" should NOT match "/bin" — this was the original bug
        // with string-based starts_with.
        assert!(!is_essential_path(Path::new("/binary-thing/foo")));
    }

    #[test]
    fn not_essential_etc_like() {
        // "/etcetera" should NOT match "/etc".
        assert!(!is_essential_path(Path::new("/etcetera/foo")));
    }

    // --- take_components ---

    #[test]
    fn take_components_nix_store() {
        let path = Path::new("/nix/store/abc-elixir/bin/iex");
        assert_eq!(take_components(path, 3), Path::new("/nix/store"));
    }

    #[test]
    fn take_components_opt_homebrew() {
        let path = Path::new("/opt/homebrew/Cellar/python/3.12/bin/python");
        assert_eq!(take_components(path, 3), Path::new("/opt/homebrew"));
    }

    #[test]
    fn take_components_snap() {
        let path = Path::new("/snap/core22/current/usr/bin/hello");
        assert_eq!(take_components(path, 2), Path::new("/snap"));
    }

    #[test]
    fn take_components_flatpak() {
        let path = Path::new("/var/lib/flatpak/app/org.foo/bin/foo");
        assert_eq!(take_components(path, 4), Path::new("/var/lib/flatpak"));
    }

    #[test]
    fn take_components_home_dotdir() {
        let path = Path::new("/home/user/.cargo/bin/rg");
        // Components: /, home, user, .cargo, bin, rg → 4 components = /home/user/.cargo
        assert_eq!(take_components(path, 4), Path::new("/home/user/.cargo"));
    }

    // --- detect_command_prefix ---

    #[test]
    fn prefix_essential_returns_none() {
        assert_eq!(detect_command_prefix(Path::new("/usr/bin/python3")), None);
        assert_eq!(detect_command_prefix(Path::new("/bin/ls")), None);
        assert_eq!(
            detect_command_prefix(Path::new("/lib/x86_64-linux-gnu/libc.so")),
            None
        );
    }

    #[test]
    fn prefix_nix_store() {
        assert_eq!(
            detect_command_prefix(Path::new("/nix/store/abc123-elixir-1.16/bin/iex")),
            Some(std::path::PathBuf::from("/nix/store"))
        );
    }

    #[test]
    fn prefix_gnu_store() {
        assert_eq!(
            detect_command_prefix(Path::new("/gnu/store/abc123-guile-3.0/bin/guile")),
            Some(std::path::PathBuf::from("/gnu/store"))
        );
    }

    #[test]
    fn prefix_homebrew() {
        assert_eq!(
            detect_command_prefix(Path::new("/opt/homebrew/Cellar/python/3.12/bin/python3")),
            Some(std::path::PathBuf::from("/opt/homebrew"))
        );
    }

    #[test]
    fn prefix_snap() {
        assert_eq!(
            detect_command_prefix(Path::new("/snap/core22/current/usr/bin/hello")),
            Some(std::path::PathBuf::from("/snap"))
        );
    }

    #[test]
    fn prefix_flatpak() {
        assert_eq!(
            detect_command_prefix(Path::new("/var/lib/flatpak/app/org.foo.Bar/bin/bar")),
            Some(std::path::PathBuf::from("/var/lib/flatpak"))
        );
    }

    #[test]
    fn prefix_home_dotdir() {
        assert_eq!(
            detect_command_prefix(Path::new("/home/user/.local/bin/tool")),
            Some(std::path::PathBuf::from("/home/user/.local"))
        );
        assert_eq!(
            detect_command_prefix(Path::new("/home/user/.cargo/bin/rg")),
            Some(std::path::PathBuf::from("/home/user/.cargo"))
        );
    }

    #[test]
    fn prefix_home_no_dotdir() {
        // /home/user/bin/custom → fallback to /home/user
        assert_eq!(
            detect_command_prefix(Path::new("/home/user/bin/custom")),
            Some(std::path::PathBuf::from("/home/user"))
        );
    }

    #[test]
    fn prefix_generic_fallback() {
        // Unknown layout under /some/custom/prefix → /some/custom
        assert_eq!(
            detect_command_prefix(Path::new("/some/custom/prefix/bin/tool")),
            Some(std::path::PathBuf::from("/some/custom"))
        );
    }
}
