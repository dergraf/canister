pub mod capabilities;
pub mod cgroups;
pub mod mac;
pub mod namespace;
pub mod notifier;
pub mod overlay;
pub mod process;
pub mod seccomp;

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

    /// Strict mode: fail hard on all setup failures.
    ///
    /// When true:
    /// - Seccomp uses KILL_PROCESS instead of ERRNO
    /// - Filesystem isolation failures are fatal
    /// - All setup failures abort instead of warning
    pub strict: bool,
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
        strict = opts.strict,
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
pub fn resolve_command(cmd: &str) -> Result<std::path::PathBuf, SandboxError> {
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

#[cfg(test)]
mod tests {
    // Removed: detect_command_prefix, is_essential_path, take_components,
    // and ESSENTIAL_PREFIXES are replaced by recipe-based auto-detection
    // and base.toml. Tests for those live in can-policy and integration tests.
}
