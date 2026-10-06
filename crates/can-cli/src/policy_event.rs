//! The `policy_resolved` event (ADR-0014).
//!
//! A run's evidence is only as trustworthy as the policy it ran under, so
//! the stream carries that policy and a hash of it. The hash lets a
//! consumer say "these two runs were governed by the same rules" without
//! diffing the whole document.

use anyhow::{Context, Result};
use can_policy::SandboxConfig;
use can_policy::config::UnsafeConfig;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The shape of the resolved policy: the `policy` of `policy_resolved`
/// and of `can run --print-policy`. Published as
/// `docs/policy-schema-v1.json` (ADR-0033); a test checks that every
/// resolved policy reads and writes back through it unchanged.
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PolicyDocument {
    #[serde(flatten)]
    pub config: SandboxConfig,
    /// The isolation-weakening settings in effect (ADR-0022).
    #[serde(rename = "unsafe")]
    pub unsafe_in_effect: UnsafeConfig,
}

/// Resolve the effective policy: the same document `can recipe show`
/// prints, with `Option` fields replaced by the values that will actually
/// be used, so nothing depends on a default that might change.
pub fn resolved(config: &SandboxConfig) -> SandboxConfig {
    let mut resolved = config.clone();
    resolved.network.egress = Some(resolved.network.egress());
    resolved.network.undeclared_hosts = Some(resolved.network.undeclared_hosts());
    resolved.filesystem.workdir = Some(resolved.filesystem.workdir());
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
///
/// The document also carries `unsafe`: the isolation-weakening settings in
/// effect (ADR-0022). The runtime config keeps several of them out of its
/// own serialization, so without it a run with `host_loopback` would leave
/// no trace of it in the evidence.
pub fn canonical(config: &SandboxConfig) -> Result<(serde_json::Value, String)> {
    let resolved = resolved(config);
    let document = PolicyDocument {
        unsafe_in_effect: UnsafeConfig::in_effect(&resolved),
        config: resolved,
    };
    let value =
        serde_json::to_value(document).context("serializing the resolved policy as JSON")?;
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

/// What `policy_resolved` will carry for `config`: the resolved policy
/// and its digest, computed by the same function (ADR-0033).
pub fn preview(config: &SandboxConfig) -> Result<serde_json::Value> {
    let (policy, policy_sha256) = canonical(config)?;
    Ok(serde_json::json!({ "policy_sha256": policy_sha256, "policy": policy }))
}

/// Print `preview` as one line of JSON, for `--print-policy`.
pub fn print(config: &SandboxConfig) -> Result<i32> {
    println!("{}", preview(config)?);
    Ok(0)
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

    #[test]
    fn the_preview_is_the_policy_resolved_event_data() {
        let (policy, digest) = canonical(&config()).expect("canonical");
        let preview = preview(&config()).expect("preview");

        assert_eq!(preview["policy_sha256"], digest.as_str());
        assert_eq!(preview["policy"], policy);
    }

    #[test]
    fn the_published_document_type_reads_every_resolved_policy() {
        let mut loose = SandboxConfig::default_deny();
        loose.network.egress = Some(EgressMode::ProxyOnly);
        loose.filesystem.read = vec!["/usr".into()];

        for config in [config(), loose, SandboxConfig::default_deny()] {
            let (policy, _) = canonical(&config).expect("canonical");
            let document: PolicyDocument =
                serde_json::from_value(policy.clone()).expect("the schema type reads the policy");
            assert_eq!(
                serde_json::to_value(document).expect("serialize"),
                policy,
                "and writes it back unchanged"
            );
        }
    }

    /// The document is serialized through `PolicyDocument` since
    /// ADR-0033; before, the config was serialized and `unsafe` inserted
    /// into it. Every consumer's baseline holds digests of the old form,
    /// so the bytes must not change.
    #[test]
    fn the_digest_is_unchanged_by_serializing_through_the_document_type() {
        let mut loose = SandboxConfig::default_deny();
        loose.network.egress = Some(EgressMode::ProxyOnly);
        loose.filesystem.read = vec!["/usr".into()];

        for config in [config(), loose, SandboxConfig::default_deny()] {
            let resolved = resolved(&config);
            let mut before = serde_json::to_value(&resolved).expect("serialize");
            before.as_object_mut().expect("object").insert(
                "unsafe".to_string(),
                serde_json::to_value(UnsafeConfig::in_effect(&resolved)).expect("serialize"),
            );
            let (now, _) = canonical(&config).expect("canonical");
            assert_eq!(
                serde_json::to_string(&now).expect("compact"),
                serde_json::to_string(&before).expect("compact")
            );
        }
    }

    #[test]
    fn published_policy_schema_is_up_to_date() {
        let rendered = format!(
            "{}\n",
            serde_json::to_string_pretty(&schemars::schema_for!(PolicyDocument))
                .expect("serialize schema")
        );
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/policy-schema-v1.json");

        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, &rendered).expect("write schema");
            return;
        }

        let published = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "missing {}: {e}\nRegenerate with UPDATE_GOLDEN=1 cargo test -p can-cli",
                path.display()
            )
        });
        assert_eq!(
            published, rendered,
            "docs/policy-schema-v1.json is stale; regenerate with UPDATE_GOLDEN=1"
        );
    }

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
            resolved.network.undeclared_hosts,
            Some(can_policy::config::UndeclaredHosts::Refuse)
        );
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

    fn with_provider_host(session_entropy_budget: Option<u64>) -> SandboxConfig {
        let mut config = config();
        config.hosts.push(can_policy::config::HostBlock {
            domain: "api.anthropic.com".to_string(),
            allow_credentials: vec!["anthropic_key".to_string()],
            session_entropy_budget,
            ..Default::default()
        });
        config
    }

    #[test]
    fn an_unset_per_host_entropy_budget_is_left_out_of_the_policy() {
        // Policies that predate the field keep the hash they had.
        let (policy, _) = canonical(&with_provider_host(None)).expect("canonical");
        let host = &policy["host"][0];
        assert_eq!(host["domain"], "api.anthropic.com");
        assert!(host.get("session_entropy_budget").is_none(), "{host}");
    }

    #[test]
    fn a_per_host_entropy_budget_is_in_the_policy_and_its_hash() {
        let (policy, with) = canonical(&with_provider_host(Some(1 << 20))).expect("canonical");
        let (_, without) = canonical(&with_provider_host(None)).expect("canonical");
        assert_eq!(policy["host"][0]["session_entropy_budget"], 1 << 20);
        assert_ne!(with, without);
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
    fn a_policy_without_unsafe_settings_says_so_explicitly() {
        let (policy, _) = canonical(&config()).expect("canonical");

        assert_eq!(
            policy["unsafe"],
            serde_json::json!({
                "unfiltered_egress": false,
                "reachable_ips": [],
                "host_loopback": false,
                "expose_ports": [],
                "seccomp_default_allow": false,
                "extra_syscalls": [],
            })
        );
    }

    #[test]
    fn host_loopback_reaches_the_policy_and_changes_the_hash() {
        let mut loopback = config();
        loopback.network.allow_host_loopback = true;

        let (policy, with_loopback) = canonical(&loopback).expect("canonical");
        let (_, without) = canonical(&config()).expect("canonical");

        assert_eq!(policy["unsafe"]["host_loopback"], true);
        assert_ne!(
            with_loopback, without,
            "a weakened sandbox must not hash like the one it weakened"
        );
    }

    #[test]
    fn every_unsafe_switch_reaches_the_policy() {
        let mut weakened = config();
        weakened.network.egress = Some(EgressMode::Direct);
        weakened.network.allow_ips = vec!["10.0.0.0/8".to_string()];
        weakened.network.ports =
            vec![can_policy::config::PortMapping::parse("127.0.0.1:8080:80").expect("port")];
        weakened.syscalls.seccomp_mode = Some(can_policy::config::SeccompMode::DenyList);
        weakened.syscalls.allow_extra = vec!["ptrace".to_string(), "sendmmsg".to_string()];

        let (policy, _) = canonical(&weakened).expect("canonical");
        let unsafe_block = &policy["unsafe"];

        assert_eq!(unsafe_block["unfiltered_egress"], true);
        assert_eq!(
            unsafe_block["reachable_ips"],
            serde_json::json!(["10.0.0.0/8"])
        );
        assert_eq!(
            unsafe_block["expose_ports"],
            serde_json::json!([{
                "host_ip": "127.0.0.1",
                "host_port": 8080,
                "container_port": 80,
                "protocol": "tcp",
            }])
        );
        assert_eq!(unsafe_block["seccomp_default_allow"], true);
        assert_eq!(
            unsafe_block["extra_syscalls"],
            serde_json::json!(["ptrace"])
        );
    }

    #[test]
    fn the_rendered_policy_reports_the_effective_egress_mode() {
        let (policy, _) = canonical(&config()).expect("canonical");

        assert_eq!(policy["network"]["egress"], "proxy");
    }

    #[test]
    fn the_rendered_policy_reports_how_undeclared_hosts_are_handled() {
        let (default_policy, default_hash) = canonical(&config()).expect("canonical");
        assert_eq!(default_policy["network"]["undeclared_hosts"], "refuse");

        let mut sink = config();
        sink.network.undeclared_hosts = Some(can_policy::config::UndeclaredHosts::Sink);
        let (sink_policy, sink_hash) = canonical(&sink).expect("canonical");

        assert_eq!(sink_policy["network"]["undeclared_hosts"], "sink");
        assert_ne!(default_hash, sink_hash);
    }

    #[test]
    fn the_rendered_policy_says_whether_the_working_directory_is_writable() {
        let (default_policy, default_hash) = canonical(&config()).expect("canonical");
        assert_eq!(default_policy["filesystem"]["workdir"], "write");

        let mut read_only = config();
        read_only.filesystem.workdir = Some(can_policy::config::WorkdirAccess::Read);
        let (read_policy, read_hash) = canonical(&read_only).expect("canonical");

        assert_eq!(read_policy["filesystem"]["workdir"], "read");
        assert_ne!(default_hash, read_hash);
    }
}
