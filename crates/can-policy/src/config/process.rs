use std::collections::HashMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::merge::union_vecs;

/// Which binaries the sandboxed process may `exec`.
///
/// Replaces the old `allow_execve = []`-means-"any" footgun with a stated
/// choice: an empty/absent list no longer silently means "exec anything."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ExecPolicy {
    /// `exec = "any"` | `"entrypoint-only"`.
    Mode(ExecMode),
    /// `exec = ["/usr/bin/node", "/nix/store/*"]` — explicit allow list
    /// (entries ending in `/*` are prefix rules).
    Allow(Vec<PathBuf>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExecMode {
    /// Any binary may be exec'd. The effective default today (full
    /// child-exec restriction needs the USER_NOTIF supervisor).
    #[default]
    Any,
    /// Only the sandbox entrypoint command may exec. Child execs are
    /// denied (enforced once USER_NOTIF execve-blocking lands; today the
    /// schema records the intent and the initial command is allowed).
    EntrypointOnly,
}

impl Default for ExecPolicy {
    fn default() -> Self {
        Self::Mode(ExecMode::Any)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessConfig {
    /// Maximum number of child PIDs allowed.
    pub max_pids: Option<u32>,

    /// Which binaries may be exec'd: `"any"`, `"entrypoint-only"`, or an
    /// explicit list of paths. `None` resolves to the default (`"any"`).
    #[serde(default)]
    pub exec: Option<ExecPolicy>,

    /// Environment variables to pass through from the host.
    /// All others are stripped.
    #[serde(default)]
    pub env_passthrough: Vec<String>,

    /// Environment variables to set in the sandbox.
    /// These are evaluated after passthrough.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl ProcessConfig {
    /// The effective exec policy (defaults to `Any`).
    pub fn exec(&self) -> ExecPolicy {
        self.exec.clone().unwrap_or_default()
    }

    pub fn merge(self, overlay: Self) -> Self {
        Self {
            max_pids: overlay.max_pids.or(self.max_pids),
            exec: overlay.exec.or(self.exec),
            env_passthrough: union_vecs(self.env_passthrough, overlay.env_passthrough),
            env: {
                let mut env = self.env;
                env.extend(overlay.env);
                env
            },
        }
    }
}
