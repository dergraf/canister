pub mod capabilities;
pub mod namespace;

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

    #[error("sandbox child process failed with status: {0}")]
    ChildFailed(i32),
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
pub(crate) fn resolve_command(cmd: &str) -> Result<std::path::PathBuf, SandboxError> {
    // If it's already an absolute path, use it directly.
    if Path::new(cmd).is_absolute() {
        return Ok(cmd.into());
    }

    // Search PATH
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join(cmd);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    Err(SandboxError::InvalidCommand(format!(
        "command not found: {cmd}"
    )))
}
