//! String-typed detector ids exposed as `pub const` so callers don't
//! sprinkle bare `"github_pat"` / `"canary_token"` literals through the
//! codebase. Each constant must correspond to an entry in
//! [`crate::registry::REGISTRY`] — the consistency check in
//! `ids::tests::registry_ids_are_consistent` enforces that. Adding a
//! detector to the registry without adding the matching const here is
//! a test failure, not silent drift.
//!
//! These constants are not type-checked against [`crate::DetectorId`];
//! they're plain `&'static str` so comparison with `detector.as_str()`
//! is a single `==`.

pub const GITHUB_PAT: &str = "github_pat";
pub const NPM_TOKEN: &str = "npm_token";
pub const AWS_ACCESS_KEY: &str = "aws_access_key";
pub const BEARER_TOKEN: &str = "bearer_token";
pub const SSH_PRIVATE_KEY: &str = "ssh_private_key";
pub const SLACK_TOKEN: &str = "slack_token";
pub const GENERIC_HIGH_ENTROPY: &str = "generic_high_entropy";
pub const CANARY_TOKEN: &str = "canary_token";
pub const OPENAI_KEY: &str = "openai_key";
pub const ANTHROPIC_KEY: &str = "anthropic_key";
pub const GOOGLE_API_KEY: &str = "google_api_key";
pub const STRIPE_KEY: &str = "stripe_key";
pub const POSTGRES_URI: &str = "postgres_uri";
pub const PKCS8_PRIVATE_KEY: &str = "pkcs8_private_key";

/// All known detector ids. Mirrors [`crate::registry::REGISTRY`] in
/// the same order. Used by the consistency check to guarantee neither
/// list drifts ahead of the other.
pub const ALL: &[&str] = &[
    GITHUB_PAT,
    NPM_TOKEN,
    AWS_ACCESS_KEY,
    BEARER_TOKEN,
    SSH_PRIVATE_KEY,
    SLACK_TOKEN,
    GENERIC_HIGH_ENTROPY,
    CANARY_TOKEN,
    OPENAI_KEY,
    ANTHROPIC_KEY,
    GOOGLE_API_KEY,
    STRIPE_KEY,
    POSTGRES_URI,
    PKCS8_PRIVATE_KEY,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::REGISTRY;
    use std::collections::HashSet;

    #[test]
    fn registry_ids_are_consistent() {
        // Every registry entry has a matching constant here.
        let consts: HashSet<&'static str> = ALL.iter().copied().collect();
        for def in REGISTRY {
            assert!(
                consts.contains(def.id),
                "registry entry {:?} has no matching constant in `ids` module",
                def.id,
            );
        }
        // And every constant corresponds to a registry entry — guards
        // against stale constants left behind after a removal.
        let reg_ids: HashSet<&'static str> = REGISTRY.iter().map(|d| d.id).collect();
        for c in ALL {
            assert!(
                reg_ids.contains(c),
                "constant {c:?} not present in REGISTRY (orphaned)",
            );
        }
        // ALL must contain unique entries.
        assert_eq!(
            ALL.len(),
            consts.len(),
            "ALL contains duplicate ids: {ALL:?}",
        );
    }
}
