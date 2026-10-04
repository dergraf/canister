//! `canister.lock`: the recipe versions a project's sandboxes are built
//! from (ADR-0026).
//!
//! The lock sits next to `canister.toml` and is checked into version
//! control with it. It pins two things:
//!
//! - each `[sources]` entry of the manifest to the revision it resolved to,
//!   so a git tag that moves cannot change the sandbox silently;
//! - each recipe a sandbox composes to the SHA-256 of its content.
//!
//! `can lock` writes it; `can up` refuses a recipe whose content no longer
//! matches, or that the lock does not name. A recipe the lock pins is as
//! reviewed as the manifest that chose it, so it may carry credential
//! scope (ADR-0026, which extends the trust gate of ADR-0008).
//!
//! This module parses, renders and checks; it does no I/O.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The lock's filename, next to `canister.toml`.
pub const LOCK_FILENAME: &str = "canister.lock";

/// The only lock format there is so far.
pub const LOCK_VERSION: u32 = 1;

const HEADER: &str = "# canister.lock — written by `can lock`, checked into version control.\n\
                      # Review a change to it like a change to canister.toml.\n\n";

/// A parsed `canister.lock`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lockfile {
    pub version: u32,
    /// Per manifest source, what it resolved to.
    #[serde(default)]
    pub sources: BTreeMap<String, LockedSource>,
    /// Per recipe name as the manifest writes it, the SHA-256 of its content.
    #[serde(default)]
    pub recipes: BTreeMap<String, String>,
}

/// A source as locked: its spec, plus the revision a git source resolved to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Why a recipe does not hold up against the lock.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LockError {
    #[error(
        "recipe '{name}' is not in canister.lock; run `can lock` and review the change it makes"
    )]
    Unlocked { name: String },
    #[error(
        "recipe '{name}' changed since it was locked (locked {locked}, now {actual}); \
         review the change and run `can lock --update`"
    )]
    Changed {
        name: String,
        locked: String,
        actual: String,
    },
    #[error("canister.lock is version {found}; this can reads version {expected}")]
    Version { found: u32, expected: u32 },
    #[error("invalid canister.lock: {0}")]
    Parse(String),
}

impl Lockfile {
    /// An empty lock of the current version.
    pub fn new() -> Self {
        Self {
            version: LOCK_VERSION,
            ..Self::default()
        }
    }

    /// Parse a lock, refusing a version this `can` does not know.
    pub fn parse(content: &str) -> Result<Self, LockError> {
        let lock: Self = toml::from_str(content).map_err(|e| LockError::Parse(e.to_string()))?;
        if lock.version != LOCK_VERSION {
            return Err(LockError::Version {
                found: lock.version,
                expected: LOCK_VERSION,
            });
        }
        Ok(lock)
    }

    /// The lock as written to disk: a header, then sorted TOML, so the same
    /// inputs always produce the same bytes and a diff shows only changes.
    pub fn render(&self) -> String {
        let body = toml::to_string(self).unwrap_or_default();
        format!("{HEADER}{body}")
    }

    /// Check a recipe's content against its pin.
    pub fn check(&self, name: &str, content: &str) -> Result<(), LockError> {
        let actual = digest(content);
        match self.recipes.get(name) {
            None => Err(LockError::Unlocked {
                name: name.to_string(),
            }),
            Some(locked) if locked.eq_ignore_ascii_case(&actual) => Ok(()),
            Some(locked) => Err(LockError::Changed {
                name: name.to_string(),
                locked: short(locked),
                actual: short(&actual),
            }),
        }
    }
}

/// The SHA-256 of a recipe's content, lowercase hex.
pub fn digest(content: &str) -> String {
    Sha256::digest(content.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn short(hex: &str) -> String {
    hex.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_with(name: &str, content: &str) -> Lockfile {
        let mut lock = Lockfile::new();
        lock.recipes.insert(name.to_string(), digest(content));
        lock
    }

    #[test]
    fn a_recipe_matching_its_pin_holds() {
        assert_eq!(
            lock_with("elixir", "a = 1\n").check("elixir", "a = 1\n"),
            Ok(())
        );
    }

    #[test]
    fn a_changed_recipe_is_refused_naming_both_digests() {
        let error = lock_with("elixir", "a = 1\n")
            .check("elixir", "a = 2\n")
            .expect_err("changed");

        assert!(matches!(error, LockError::Changed { .. }));
        assert!(error.to_string().contains("can lock --update"));
    }

    #[test]
    fn a_recipe_the_lock_does_not_name_is_refused() {
        let error = lock_with("elixir", "a = 1\n")
            .check("team/internal-api", "a = 1\n")
            .expect_err("unlocked");

        assert_eq!(
            error,
            LockError::Unlocked {
                name: "team/internal-api".to_string()
            }
        );
    }

    #[test]
    fn a_round_trip_is_lossless_and_byte_stable() {
        let mut lock = lock_with("team/internal-api", "x = 1\n");
        lock.recipes.insert("elixir".to_string(), digest("y = 2\n"));
        lock.sources.insert(
            "team".to_string(),
            LockedSource {
                git: Some("https://git.example/recipes".to_string()),
                tag: Some("v1".to_string()),
                rev: Some("a".repeat(40)),
                path: None,
            },
        );

        let rendered = lock.render();
        assert!(rendered.starts_with("# canister.lock"));
        assert_eq!(Lockfile::parse(&rendered), Ok(lock.clone()));
        assert_eq!(Lockfile::parse(&rendered).map(|l| l.render()), Ok(rendered));
    }

    #[test]
    fn an_unknown_version_or_key_is_refused() {
        assert!(matches!(
            Lockfile::parse("version = 2\n"),
            Err(LockError::Version { found: 2, .. })
        ));
        assert!(matches!(
            Lockfile::parse("version = 1\nextra = true\n"),
            Err(LockError::Parse(_))
        ));
    }

    #[test]
    fn the_digest_is_sha256_hex() {
        assert_eq!(
            digest(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
