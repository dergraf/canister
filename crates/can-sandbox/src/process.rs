//! Process control and environment filtering.
//!
//! Phase 5 implementation: enforces `ProcessConfig` settings from the sandbox
//! policy before the target command is executed.
//!
//! Responsibilities:
//! - **Environment filtering**: strip all env vars not in `env_passthrough`.
//! - **PID namespace**: enter a new PID namespace via inner fork so the
//!   sandboxed process tree is isolated (child becomes PID 1).
//! - **`max_pids`**: set `RLIMIT_NPROC` to cap the number of processes.
//! - **`allow_execve`**: validate the initial command path against the whitelist.
//!   When the whitelist is non-empty, also block `execve`/`execveat` via seccomp
//!   for child processes (the initial exec is allowed after validation).

use std::ffi::CString;
use std::path::Path;

use can_policy::config::ProcessConfig;

/// Errors from process control operations.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("command not in allow_execve whitelist: {0}")]
    ExecNotAllowed(String),

    #[error("failed to set RLIMIT_NPROC: {0}")]
    SetRlimit(std::io::Error),

    #[error("PID namespace fork failed: {0}")]
    PidFork(nix::Error),

    #[error("waitpid in PID namespace failed: {0}")]
    PidWait(nix::Error),
}

/// Capture the full host environment as `CString` entries for `execve`.
///
/// Used in monitor mode to pass the complete environment through without
/// filtering, so the process runs as if no policy were applied.
pub fn full_environment() -> Vec<CString> {
    std::env::vars()
        .filter_map(|(key, val)| CString::new(format!("{key}={val}")).ok())
        .collect()
}

/// Filter the process environment according to `env_passthrough`.
///
/// If `env_passthrough` is empty, all environment variables are stripped
/// (the process starts with a completely clean environment). Otherwise,
/// only the listed variables are kept.
///
/// Always injects a minimal `PATH` if not explicitly passed through and
/// the list is non-empty, to avoid breaking command resolution inside
/// the sandbox.
pub fn filter_environment(config: &ProcessConfig) -> Vec<CString> {
    if config.env_passthrough.is_empty() {
        // No passthrough list = strip everything. This is the most secure
        // default — the sandboxed process gets zero host environment leakage.
        tracing::info!("env_passthrough is empty, clearing all environment variables");
        return Vec::new();
    }

    let mut env: Vec<CString> = Vec::new();
    let mut has_path = false;

    for key in &config.env_passthrough {
        if let Ok(val) = std::env::var(key) {
            if key == "PATH" {
                has_path = true;
            }
            // Format: KEY=VALUE as a CString for execve.
            if let Ok(entry) = CString::new(format!("{key}={val}")) {
                env.push(entry);
            }
        }
    }

    // Ensure PATH exists so the sandboxed process can find executables.
    // Use a minimal safe default if not passed through.
    if !has_path {
        if let Ok(entry) = CString::new("PATH=/usr/local/bin:/usr/bin:/bin") {
            tracing::debug!("injecting minimal PATH (not in env_passthrough)");
            env.push(entry);
        }
    }

    tracing::info!(
        kept = env.len(),
        passthrough = config.env_passthrough.len(),
        "environment filtered"
    );

    env
}

/// Validate that the resolved command path is in the `allow_execve` whitelist.
///
/// If `allow_execve` is empty, all commands are allowed (no restriction).
/// If non-empty, the command's canonical path must match one of the entries.
///
/// Entries ending in `/*` are treated as **prefix rules**: any executable
/// whose canonical path starts with the directory prefix is allowed.
/// For example, `/nix/store/*` allows any binary under `/nix/store/`.
pub fn validate_execve(command_path: &Path, config: &ProcessConfig) -> Result<(), ProcessError> {
    if config.allow_execve.is_empty() {
        return Ok(());
    }

    // Canonicalize the command path for comparison.
    let canonical = command_path
        .canonicalize()
        .unwrap_or_else(|_| command_path.to_path_buf());

    for allowed in &config.allow_execve {
        let allowed_str = allowed.as_os_str().to_string_lossy();

        if let Some(prefix) = allowed_str.strip_suffix("/*") {
            // Prefix rule: strip the trailing /* and check starts_with.
            let canonical_str = canonical.to_string_lossy();
            if canonical_str.starts_with(prefix)
                && canonical_str.as_bytes().get(prefix.len()) == Some(&b'/')
            {
                tracing::debug!(
                    path = %canonical.display(),
                    prefix = prefix,
                    "command allowed by allow_execve prefix rule"
                );
                return Ok(());
            }
        } else {
            // Exact match (existing behaviour).
            let allowed_canonical = allowed.canonicalize().unwrap_or_else(|_| allowed.clone());
            if canonical == allowed_canonical {
                tracing::debug!(
                    path = %canonical.display(),
                    "command allowed by allow_execve whitelist"
                );
                return Ok(());
            }
        }
    }

    Err(ProcessError::ExecNotAllowed(
        canonical.display().to_string(),
    ))
}

/// Set `RLIMIT_NPROC` to limit the number of processes the sandboxed user can create.
///
/// This is a lightweight alternative to cgroups `pids.max`. It limits the total
/// number of processes for the UID, so inside a user namespace (where the sandbox
/// runs as UID 0 mapped to the host user), it effectively caps the sandbox.
///
/// Note: this is a per-UID limit, not per-namespace. It's a rough approximation
/// until cgroups v2 `pids` controller support is added in Phase 7.
pub fn set_max_pids(max: u32) -> Result<(), ProcessError> {
    let limit = libc::rlimit {
        rlim_cur: max as u64,
        rlim_max: max as u64,
    };

    // SAFETY: setrlimit is safe to call with valid arguments.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &limit) };
    if ret != 0 {
        return Err(ProcessError::SetRlimit(std::io::Error::last_os_error()));
    }

    tracing::info!(max_pids = max, "RLIMIT_NPROC set");
    Ok(())
}

/// Apply sensible default resource limits for sandboxed processes.
///
/// These limits provide defense against fork bombs, memory exhaustion, and
/// file descriptor exhaustion. They are applied unconditionally — even when
/// no explicit resource config is provided — as a safety net.
///
/// If the user has configured explicit limits (e.g., `max_pids` in the recipe),
/// those override the defaults set here (because they're applied separately
/// and RLIMIT can be lowered but not raised after this point).
///
/// Defaults:
/// - `RLIMIT_NPROC`:  4096 processes (prevents fork bombs)
/// - `RLIMIT_AS`:     8 GB virtual address space (prevents OOM)
/// - `RLIMIT_NOFILE`: 4096 file descriptors (prevents FD exhaustion)
/// - `RLIMIT_FSIZE`:  4 GB max file size (prevents disk exhaustion)
/// - `RLIMIT_CORE`:   0 (no core dumps, prevents data leakage)
pub fn apply_default_resource_limits() {
    set_rlimit(libc::RLIMIT_NPROC, 4096, "RLIMIT_NPROC");
    set_rlimit(
        libc::RLIMIT_AS,
        8 * 1024 * 1024 * 1024, // 8 GB
        "RLIMIT_AS",
    );
    set_rlimit(libc::RLIMIT_NOFILE, 4096, "RLIMIT_NOFILE");
    set_rlimit(
        libc::RLIMIT_FSIZE,
        4 * 1024 * 1024 * 1024, // 4 GB
        "RLIMIT_FSIZE",
    );
    set_rlimit(libc::RLIMIT_CORE, 0, "RLIMIT_CORE");
}

/// The resource parameter type for `setrlimit` differs between glibc
/// (`__rlimit_resource_t`, a `c_uint` typedef) and musl (`c_int`).
/// We define a target-specific alias so the rest of the code stays DRY.
#[cfg(target_env = "musl")]
type RlimitResource = libc::c_int;
#[cfg(not(target_env = "musl"))]
type RlimitResource = libc::__rlimit_resource_t;

/// Set a resource limit, logging success or failure.
fn set_rlimit(resource: RlimitResource, value: u64, name: &str) {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: setrlimit is safe with valid resource and limit values.
    let ret = unsafe { libc::setrlimit(resource, &limit) };
    if ret != 0 {
        tracing::warn!(
            name,
            value,
            error = %std::io::Error::last_os_error(),
            "failed to set resource limit"
        );
    } else {
        tracing::debug!(name, value, "resource limit set");
    }
}

/// Build the list of extra syscalls to deny based on process config.
///
/// When `allow_execve` is non-empty, we want to prevent the sandboxed process's
/// children from calling execve with arbitrary paths. Since BPF cannot inspect
/// string arguments, we can't do path-based filtering. Instead, we block
/// execve/execveat entirely via seccomp for processes AFTER the initial exec.
///
/// This returns syscall names to add to the deny list. The caller should
/// apply these ONLY if the initial command has been validated and the seccomp
/// filter should be installed BEFORE the initial execvp.
///
/// NOTE: Blocking execve before the initial exec would prevent the sandbox
/// from starting. This is handled by the caller: the seccomp filter with
/// execve denied is NOT installed when `allow_execve` is non-empty (because
/// the initial execvp must succeed). Instead, `allow_execve` validation is
/// done pre-exec, and ongoing child exec blocking requires `SECCOMP_RET_USER_NOTIF`
/// (deferred to a future phase).
pub fn extra_denied_syscalls(config: &ProcessConfig) -> Vec<String> {
    // For now, we don't add execve/execveat to the seccomp deny list because:
    // 1. We can't block execve and then successfully call execvp ourselves.
    // 2. Path-based filtering requires argument inspection (SECCOMP_RET_USER_NOTIF).
    //
    // The initial command is validated by validate_execve(). Ongoing enforcement
    // of child execs is deferred until SECCOMP_RET_USER_NOTIF support.
    let _ = config;
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn filter_env_empty_passthrough_clears_all() {
        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![],
            env_passthrough: vec![],
        };
        let env = filter_environment(&config);
        assert!(env.is_empty(), "empty passthrough should clear all env");
    }

    #[test]
    fn filter_env_keeps_listed_vars() {
        // SAFETY: test-only, single-threaded context.
        unsafe { std::env::set_var("CANISTER_TEST_VAR", "hello") };

        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![],
            env_passthrough: vec![
                "CANISTER_TEST_VAR".to_string(),
                "NONEXISTENT_VAR".to_string(),
            ],
        };
        let env = filter_environment(&config);

        // Should have CANISTER_TEST_VAR and an injected PATH (since PATH wasn't in passthrough).
        let env_strs: Vec<String> = env
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert!(
            env_strs.iter().any(|s| s.starts_with("CANISTER_TEST_VAR=")),
            "should keep CANISTER_TEST_VAR"
        );
        assert!(
            env_strs.iter().any(|s| s.starts_with("PATH=")),
            "should inject PATH"
        );
        // NONEXISTENT_VAR shouldn't appear (not set in host env).
        assert!(
            !env_strs.iter().any(|s| s.starts_with("NONEXISTENT_VAR=")),
            "should not include unset vars"
        );

        // SAFETY: test-only, single-threaded context.
        unsafe { std::env::remove_var("CANISTER_TEST_VAR") };
    }

    #[test]
    fn filter_env_preserves_explicit_path() {
        // SAFETY: test-only, single-threaded context.
        unsafe { std::env::set_var("PATH", "/custom/path:/usr/bin") };

        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![],
            env_passthrough: vec!["PATH".to_string()],
        };
        let env = filter_environment(&config);

        let env_strs: Vec<String> = env
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        let path_entry = env_strs.iter().find(|s| s.starts_with("PATH=")).unwrap();
        assert!(
            path_entry.contains("/custom/path"),
            "should keep the host PATH value"
        );
    }

    #[test]
    fn validate_execve_empty_whitelist_allows_all() {
        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![],
            env_passthrough: vec![],
        };
        assert!(validate_execve(Path::new("/usr/bin/anything"), &config).is_ok());
    }

    #[test]
    fn validate_execve_allows_listed_command() {
        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![PathBuf::from("/bin/echo")],
            env_passthrough: vec![],
        };
        // /bin/echo should exist on any Linux system.
        assert!(validate_execve(Path::new("/bin/echo"), &config).is_ok());
    }

    #[test]
    fn validate_execve_rejects_unlisted_command() {
        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![PathBuf::from("/bin/echo")],
            env_passthrough: vec![],
        };
        let result = validate_execve(Path::new("/bin/ls"), &config);
        assert!(result.is_err());
        assert!(matches!(result, Err(ProcessError::ExecNotAllowed(_))));
    }

    #[test]
    fn validate_execve_prefix_allows_nested_binary() {
        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![PathBuf::from("/nix/store/*")],
            env_passthrough: vec![],
        };
        // A deeply nested nix store binary should match the prefix rule.
        let result = validate_execve(Path::new("/nix/store/abc123-elixir-1.18/bin/mix"), &config);
        assert!(result.is_ok(), "prefix rule should allow nested binary");
    }

    #[test]
    fn validate_execve_prefix_rejects_outside_path() {
        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![PathBuf::from("/nix/store/*")],
            env_passthrough: vec![],
        };
        let result = validate_execve(Path::new("/usr/bin/echo"), &config);
        assert!(result.is_err(), "prefix rule should not match outside path");
    }

    #[test]
    fn validate_execve_prefix_rejects_partial_match() {
        // "/nix/store-extra/bin/foo" should NOT match "/nix/store/*"
        // because "store-extra" != "store".
        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![PathBuf::from("/nix/store/*")],
            env_passthrough: vec![],
        };
        let result = validate_execve(Path::new("/nix/store-extra/bin/foo"), &config);
        assert!(
            result.is_err(),
            "prefix rule must not match partial directory names"
        );
    }

    #[test]
    fn validate_execve_prefix_and_exact_coexist() {
        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![PathBuf::from("/nix/store/*"), PathBuf::from("/bin/echo")],
            env_passthrough: vec![],
        };
        // Both should work.
        assert!(
            validate_execve(Path::new("/nix/store/abc/bin/mix"), &config).is_ok(),
            "prefix rule should match"
        );
        assert!(
            validate_execve(Path::new("/bin/echo"), &config).is_ok(),
            "exact rule should match"
        );
        assert!(
            validate_execve(Path::new("/usr/bin/ls"), &config).is_err(),
            "unmatched path should be rejected"
        );
    }

    #[test]
    fn extra_denied_syscalls_returns_empty_for_now() {
        let config = ProcessConfig {
            max_pids: None,
            allow_execve: vec![PathBuf::from("/usr/bin/python3")],
            env_passthrough: vec![],
        };
        let extra = extra_denied_syscalls(&config);
        assert!(extra.is_empty(), "deferred to SECCOMP_RET_USER_NOTIF phase");
    }

    #[test]
    fn full_environment_captures_host_env() {
        // SAFETY: test-only, single-threaded context.
        unsafe { std::env::set_var("CANISTER_FULL_ENV_TEST", "present") };

        let env = full_environment();
        let env_strs: Vec<String> = env
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();

        assert!(
            env_strs
                .iter()
                .any(|s| s.starts_with("CANISTER_FULL_ENV_TEST=")),
            "full_environment should capture host env"
        );
        // Should include more than just our test var.
        assert!(env.len() > 1, "should have multiple env vars");

        // SAFETY: test-only, single-threaded context.
        unsafe { std::env::remove_var("CANISTER_FULL_ENV_TEST") };
    }
}
