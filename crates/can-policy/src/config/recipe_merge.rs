//! `RecipeFile::merge` — the top-level composition of per-section merges.
//!
//! Per-section merge logic lives next to each `FooConfig`. This file is
//! just the thin glue that calls them in order.

use super::merge::merge_or_bool;
use super::recipe::RecipeFile;

impl RecipeFile {
    /// Merge another recipe on top of this one (layered composition).
    ///
    /// Merge rules per section live in each `FooConfig::merge` — this
    /// function only composes them. The general shape across sections:
    /// - `Vec` fields: union (deduplicated, preserving order)
    /// - `Option<T>` scalars: last-Some-wins
    /// - `Option<bool>` security escalations (`strict`, `dlp.enabled`,
    ///   `dlp.canary_tokens`): OR — any `Some(true)` wins
    /// - `RecipeMeta`: overlay wins if present
    pub fn merge(self, overlay: RecipeFile) -> RecipeFile {
        RecipeFile {
            recipe: overlay.recipe.or(self.recipe),
            strict: merge_or_bool(self.strict, overlay.strict),
            filesystem: self.filesystem.merge(overlay.filesystem),
            network: self.network.merge(overlay.network),
            process: self.process.merge(overlay.process),
            resources: self.resources.merge(overlay.resources),
            syscalls: self.syscalls.merge(overlay.syscalls),
            proxy: self.proxy.merge(overlay.proxy),
        }
    }
}
