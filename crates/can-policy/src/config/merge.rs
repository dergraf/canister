//! Merge primitives shared across config sections.
//!
//! Three patterns:
//! - **Last-Some-wins** for plain `Option<T>` (a missing overlay preserves the base).
//! - **OR semantics** for `Option<bool>` that represents a security
//!   escalation (`strict`, `enabled`, `canary_tokens`): once `Some(true)`,
//!   never reset.
//! - **Union with first-occurrence preservation** for `Vec<T>`.
//!
//! Per-section [`FooConfig::merge`] methods consume these primitives,
//! and `RecipeFile::merge` composes the per-section calls.

use std::collections::HashSet;
use std::hash::Hash;

/// Merge two `Vec<T>` by appending, deduplicating (preserving first
/// occurrence order).
pub fn union_vecs<T: Clone + Eq + Hash>(base: Vec<T>, overlay: Vec<T>) -> Vec<T> {
    let mut seen = HashSet::with_capacity(base.len() + overlay.len());
    let mut result = Vec::with_capacity(base.len() + overlay.len());
    for item in base.into_iter().chain(overlay) {
        if seen.insert(item.clone()) {
            result.push(item);
        }
    }
    result
}

/// OR semantics for `Option<bool>` where `Some(true)` is a one-way
/// security escalation. Used for `strict`, `dlp.enabled`,
/// `dlp.canary_tokens`.
///
/// ```text
/// (true,  _)         → true
/// (_, true)          → true
/// (Some(false), _)   → keep overlay if Some, else base
/// (None, x)          → x
/// ```
pub fn merge_or_bool(base: Option<bool>, overlay: Option<bool>) -> Option<bool> {
    match (base, overlay) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (_, s @ Some(_)) => s,
        (s, None) => s,
    }
}
