use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    /// Memory limit in megabytes.
    pub memory_mb: Option<u64>,

    /// CPU limit as a percentage (e.g., 50 = 50% of one core).
    pub cpu_percent: Option<u32>,
}

impl ResourceConfig {
    /// Last-Some-wins per field. A missing overlay preserves the base.
    pub fn merge(self, overlay: Self) -> Self {
        Self {
            memory_mb: overlay.memory_mb.or(self.memory_mb),
            cpu_percent: overlay.cpu_percent.or(self.cpu_percent),
        }
    }
}
