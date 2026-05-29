use std::collections::HashSet;
use std::path::PathBuf;

/// Policy for the supervisor to enforce.
///
/// Since egress filtering moved to the network topology (the worker has no
/// uplink in proxy mode) and socket/clone gating moved to the static BPF
/// prelude, the supervisor's only remaining job is the per-exec path
/// allow-list. This struct therefore carries just the exec policy.
#[derive(Debug, Clone, Default)]
pub struct NotifierPolicy {
    /// Allowed executable paths for execve()/execveat() — exact matches.
    pub allowed_exec_paths: HashSet<PathBuf>,

    /// Allowed executable path prefixes for execve()/execveat().
    /// Entries from `allow_execve` that end in `/*` are stored here as
    /// the prefix (without the trailing `/*`). A path matches if it
    /// starts with the prefix followed by `/`.
    pub allowed_exec_prefixes: Vec<PathBuf>,
}
