pub mod capabilities;
pub mod cgroups;
pub mod mac;
pub mod namespace;
pub mod notifier;
pub mod overlay;
pub mod pipe_protocol;
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

    /// Structured event stream settings (ADR-0010). `None` disables
    /// event emission entirely — the default behavior of `can`.
    ///
    /// The CLI process has already opened its own stream; the forked proxy
    /// process opens a second connection from this config.
    pub events: Option<can_events::EventConfig>,

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

/// Resolve a command to its full path, the way a shell finds it.
///
/// A name without `/` is looked up on `PATH`; a path with `/` is taken as
/// written, relative to the working directory when it is not absolute.
///
/// Returns the **canonicalized** path with all symlinks resolved. This is
/// critical for sandboxing: the kernel follows symlinks during execve, and
/// every intermediate target must exist inside the sandbox. By canonicalizing
/// upfront we avoid having to replicate multi-hop symlink chains (common
/// with Nix/home-manager) inside the isolated filesystem.
pub fn resolve_command(cmd: &str) -> Result<std::path::PathBuf, SandboxError> {
    let cwd = std::env::current_dir().ok();
    resolve_command_in(cmd, cwd.as_deref(), std::env::var("PATH").ok().as_deref())
}

/// [`resolve_command`] with the working directory and `PATH` given.
pub(crate) fn resolve_command_in(
    cmd: &str,
    cwd: Option<&Path>,
    path_var: Option<&str>,
) -> Result<std::path::PathBuf, SandboxError> {
    let written = Path::new(cmd);

    let found = if written.is_absolute() {
        Some(written.to_path_buf())
    } else if cmd.contains('/') {
        cwd.map(|dir| dir.join(written))
            .filter(|candidate| candidate.exists())
    } else {
        path_var.and_then(|path_var| {
            path_var
                .split(':')
                .map(|dir| Path::new(dir).join(cmd))
                .find(|candidate| candidate.exists())
        })
    }
    .ok_or_else(|| SandboxError::InvalidCommand(format!("command not found: {cmd}")))?;

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

    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    /// A scratch directory with `bin/tool` (executable) and
    /// `venv/bin/python` (a symlink to it), removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("can-resolve-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("bin")).expect("scratch bin dir");
            std::fs::create_dir_all(dir.join("venv/bin")).expect("scratch venv dir");
            let tool = dir.join("bin/tool");
            std::fs::write(&tool, "#!/bin/sh\n").expect("scratch tool");
            std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755))
                .expect("scratch tool mode");
            symlink(&tool, dir.join("venv/bin/python")).expect("scratch symlink");
            Self(dir.canonicalize().expect("scratch canonical"))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_bare_name_is_looked_up_on_path() {
        let scratch = Scratch::new("bare");
        let path = scratch.0.join("bin");

        let resolved = resolve_command_in("tool", None, path.to_str()).expect("found on PATH");

        assert_eq!(resolved, scratch.0.join("bin/tool"));
    }

    #[test]
    fn a_relative_path_resolves_against_the_working_directory_like_a_shell() {
        let scratch = Scratch::new("relative");

        let resolved =
            resolve_command_in("bin/tool", Some(&scratch.0), Some("/nonexistent")).expect("found");

        assert_eq!(resolved, scratch.0.join("bin/tool"));
    }

    #[test]
    fn a_relative_path_is_not_searched_on_path() {
        let scratch = Scratch::new("not-on-path");
        let elsewhere = std::env::temp_dir();

        let result = resolve_command_in("bin/tool", Some(&elsewhere), scratch.0.to_str());

        assert!(
            result.is_err(),
            "bin/tool names a file under the working directory only"
        );
    }

    #[test]
    fn the_resolved_path_follows_symlinks_to_the_target() {
        let scratch = Scratch::new("symlink");

        let resolved =
            resolve_command_in("venv/bin/python", Some(&scratch.0), None).expect("found");

        assert_eq!(resolved, scratch.0.join("bin/tool"));
    }

    #[test]
    fn a_missing_command_names_itself() {
        let error = resolve_command_in("no-such-tool", None, Some("/nonexistent"))
            .expect_err("nothing to find");

        assert!(error.to_string().contains("no-such-tool"));
    }
}
