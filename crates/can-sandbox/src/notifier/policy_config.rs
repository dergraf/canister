//! Build a `NotifierPolicy` (the supervisor's exec path allow-list) from a
//! `SandboxConfig`.

use std::collections::HashSet;
use std::path::PathBuf;

use super::policy::NotifierPolicy;

/// Build a `NotifierPolicy` from the sandbox configuration.
///
/// Only the exec allow-list is relevant to the supervisor now: egress is
/// enforced by the network topology and socket/clone gating by static BPF.
pub fn policy_from_config(config: &can_policy::SandboxConfig) -> NotifierPolicy {
    // Allowed exec paths/prefixes. Entries ending in `/*` are prefix rules
    // (match any path under that directory). All others are exact matches.
    let mut allowed_exec_paths: HashSet<PathBuf> = HashSet::new();
    let mut allowed_exec_prefixes: Vec<PathBuf> = Vec::new();

    // Only an explicit `exec = [paths]` policy seeds the notifier's exec
    // allow list; `any` / `entrypoint-only` carry no path list here.
    let exec_allow = match config.process.exec() {
        can_policy::config::ExecPolicy::Allow(paths) => paths,
        can_policy::config::ExecPolicy::Mode(_) => Vec::new(),
    };
    for p in &exec_allow {
        let s = p.as_os_str().to_string_lossy();
        if let Some(prefix_str) = s.strip_suffix("/*") {
            let prefix_path = PathBuf::from(prefix_str);
            let canonical = prefix_path
                .canonicalize()
                .unwrap_or_else(|_| prefix_path.clone());
            allowed_exec_prefixes.push(canonical);
        } else {
            let canonical = p.canonicalize().unwrap_or_else(|_| p.clone());
            allowed_exec_paths.insert(canonical);
        }
    }

    NotifierPolicy {
        allowed_exec_paths,
        allowed_exec_prefixes,
    }
}
