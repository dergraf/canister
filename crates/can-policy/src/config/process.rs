use std::collections::HashMap;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::merge::union_vecs;

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProcessConfig {
    /// Maximum number of child PIDs allowed.
    pub max_pids: Option<u32>,

    /// Paths to executables the sandboxed process may exec.
    #[serde(default)]
    pub allow_execve: Vec<PathBuf>,

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
    pub fn merge(self, overlay: Self) -> Self {
        Self {
            max_pids: overlay.max_pids.or(self.max_pids),
            allow_execve: union_vecs(self.allow_execve, overlay.allow_execve),
            env_passthrough: union_vecs(self.env_passthrough, overlay.env_passthrough),
            env: {
                let mut env = self.env;
                env.extend(overlay.env);
                env
            },
        }
    }
}
