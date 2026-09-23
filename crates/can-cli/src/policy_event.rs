//! The `policy_resolved` event (ADR-0014).
//!
//! A run's evidence is only as trustworthy as the policy it ran under, so
//! the stream carries that policy and a hash of it. The hash lets a
//! consumer say "these two runs were governed by the same rules" without
//! diffing the whole document.

use anyhow::{Context, Result};
use can_policy::SandboxConfig;
use sha2::{Digest, Sha256};

/// Resolve the effective policy: the same document `can recipe show`
/// prints, with `Option` fields replaced by the values that will actually
/// be used, so nothing depends on a default that might change.
pub fn resolved(config: &SandboxConfig) -> SandboxConfig {
    let mut resolved = config.clone();
    resolved.network.egress = Some(resolved.network.egress());
    resolved.syscalls.seccomp_mode = Some(resolved.syscalls.seccomp_mode());
    resolved
}

/// Render the resolved policy as JSON plus its canonical hash.
///
/// Canonicalization (documented in ADR-0014): the policy is serialized to
/// a `serde_json::Value`, whose object keys are ordered
/// lexicographically, then written compactly with no insignificant
/// whitespace. The SHA-256 is taken over exactly those UTF-8 bytes, so a
/// consumer can recompute it from the `policy` field alone.
pub fn canonical(config: &SandboxConfig) -> Result<(serde_json::Value, String)> {
    let value = serde_json::to_value(resolved(config))
        .context("serializing the resolved policy as JSON")?;
    let canonical = serde_json::to_string(&value).context("canonicalizing the resolved policy")?;

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }

    Ok((value, hex))
}

/// Emit `policy_resolved`. A no-op unless an event stream is installed.
pub fn emit(config: &SandboxConfig) -> Result<()> {
    if !can_events::enabled() {
        return Ok(());
    }

    let (policy, policy_sha256) = canonical(config)?;
    can_events::emit(can_events::Event::PolicyResolved(
        can_events::schema::PolicyResolved {
            policy_sha256,
            policy,
        },
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use can_policy::config::EgressMode;

    fn config() -> SandboxConfig {
        let mut config = SandboxConfig::default_deny();
        config.network.egress = Some(EgressMode::ProxyOnly);
        config
    }

    #[test]
    fn defaults_are_resolved_to_explicit_values() {
        let bare = SandboxConfig::default_deny();
        assert!(bare.network.egress.is_none(), "precondition");

        let resolved = resolved(&bare);

        assert_eq!(resolved.network.egress, Some(bare.network.egress()));
        assert_eq!(
            resolved.syscalls.seccomp_mode,
            Some(bare.syscalls.seccomp_mode())
        );
    }

    #[test]
    fn the_hash_is_stable_across_calls() {
        let (_, first) = canonical(&config()).expect("canonical");
        let (_, second) = canonical(&config()).expect("canonical");

        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn an_implicit_and_an_explicit_default_hash_alike() {
        // `egress` unset resolves to the same effective value as `egress`
        // set to that default, so the two policies must not look different.
        let implicit = SandboxConfig::default_deny();
        let mut explicit = SandboxConfig::default_deny();
        explicit.network.egress = Some(implicit.network.egress());

        let (_, implicit_hash) = canonical(&implicit).expect("canonical");
        let (_, explicit_hash) = canonical(&explicit).expect("canonical");

        assert_eq!(implicit_hash, explicit_hash);
    }

    #[test]
    fn a_policy_change_changes_the_hash() {
        let mut changed = config();
        changed.hosts.push(can_policy::config::HostBlock {
            domain: "api.anthropic.com".to_string(),
            ..Default::default()
        });

        let (_, before) = canonical(&config()).expect("canonical");
        let (_, after) = canonical(&changed).expect("canonical");

        assert_ne!(before, after);
    }

    #[test]
    fn the_hash_covers_exactly_the_emitted_policy() {
        let (policy, hash) = canonical(&config()).expect("canonical");

        let recomputed = {
            let canonical = serde_json::to_string(&policy).expect("re-serialize");
            let mut hasher = Sha256::new();
            hasher.update(canonical.as_bytes());
            hasher
                .finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };

        assert_eq!(
            hash, recomputed,
            "a consumer can verify from `policy` alone"
        );
    }

    #[test]
    fn the_rendered_policy_reports_the_effective_egress_mode() {
        let (policy, _) = canonical(&config()).expect("canonical");

        assert_eq!(policy["network"]["egress"], "proxy");
    }
}
