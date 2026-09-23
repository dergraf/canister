//! Per-destination egress contracts.
//!
//! See `docs/adr/0007-per-destination-egress-contracts.md` for the
//! design rationale. The short version: every FQDN a sandbox is
//! allowed to talk to is described by exactly one `[[host]]` block
//! (with multiple blocks at the same domain merging additively). The
//! block answers every question about that upstream in one place:
//!
//! - **Connect permission** — having a `[[host]]` entry at all is the
//!   permission to dial the host.
//! - **Request shape** — `methods`, `content_types`, `paths`,
//!   `max_request_bytes` gate the request shape *before* the DLP
//!   scanner runs. A POST `image/png` to a JSON-only API is refused
//!   without ever decoding the body.
//! - **Credential scope** — `allow_credentials` names the DLP
//!   detectors (`github_pat`, `npm_token`, …) whose findings on this
//!   host should be downgraded from `Block` to `Warn`.
//! - **Mode override** — `contract_mode` per-block can flip one
//!   upstream to `Relaxed` (no shape gate) without changing the
//!   global default.
//!
//! Minimum-viable form is `domain = "x"`: any method, any content
//! type, any path, any size, no credential whitelist.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::merge::union_vecs;

/// Per-host egress contract. See module docs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostBlock {
    /// FQDN this contract applies to. Wildcards (`*.github.com`) match
    /// any single subdomain level; bare suffixes (`github.com`) match
    /// only the exact host. Precedence is most-specific-wins when
    /// multiple wildcards match a single request — same rule as
    /// elsewhere in the policy layer.
    pub domain: String,

    /// HTTP methods this host accepts. Empty (the default) = any
    /// method. Method matching is case-insensitive.
    #[serde(default)]
    pub methods: Vec<String>,

    /// Content-Type values this host accepts on request bodies.
    /// Matched against the leading `mime/subtype` portion of the
    /// Content-Type header (parameters like `; charset=utf-8` are
    /// ignored). Empty = any content type.
    #[serde(default)]
    pub content_types: Vec<String>,

    /// Path prefixes that requests must start with. Empty = any path.
    /// Useful for an upstream where only a subtree is a legitimate
    /// target (e.g. `["/repos/", "/user/"]` for GitHub).
    #[serde(default)]
    pub paths: Vec<String>,

    /// Maximum request-body byte size accepted. `None` = no
    /// per-host cap (the global `max_streamed_body_bytes` still
    /// applies as a backstop).
    #[serde(default)]
    pub max_request_bytes: Option<u64>,

    /// DLP detector ids whose findings on this host downgrade from
    /// `Block` to `Warn`. Co-located here so the full "what is this
    /// upstream" picture (connect permission + shape + credential
    /// scope) lives in one block.
    #[serde(default)]
    pub allow_credentials: Vec<String>,

    /// Optional per-host override of the global
    /// [`super::network::NetworkConfig::contract_mode`]. Mainly used
    /// to carve out one known-weird upstream as `Relaxed` while
    /// keeping the rest of the recipe `Strict`. `None` = inherit the
    /// global default.
    #[serde(default)]
    pub contract_mode: Option<ContractMode>,

    /// Route requests for this host to a service on the *host's*
    /// loopback instead of the real destination, as `loopback:<port>`
    /// (ADR-0013). The sandboxed workload still calls
    /// `https://<domain>/...` and the proxy still terminates TLS with its
    /// dynamic CA, applies the contract and scans with DLP; only the dial
    /// target changes, and the hop to the mock is plain HTTP over
    /// loopback. Requires `[unsafe] host_loopback = true`.
    #[serde(default)]
    pub upstream: Option<String>,
}

/// Where a `[[host]]` block's traffic is actually dialled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTarget {
    /// A port on the host's loopback interface, reached through the
    /// pasta gateway.
    Loopback(u16),
}

/// Error returned for a malformed `upstream` value.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid upstream '{value}' for host '{domain}': expected `loopback:<port>`")]
pub struct UpstreamParseError {
    pub domain: String,
    pub value: String,
}

impl HostBlock {
    /// Merge two blocks targeting the same domain. Used by
    /// `RecipeFile::merge` to compose canister-shipped service
    /// contracts with project-local extensions. Semantics:
    ///
    /// - Vec fields union (preserving first-seen order).
    /// - `max_request_bytes` takes the **max** of the two (most
    ///   permissive wins — a project recipe can grow the cap, not
    ///   shrink it).
    /// - `contract_mode` is last-Some-wins, matching the rest of the
    ///   `Option<T>` policy fields.
    pub fn merge(self, overlay: Self) -> Self {
        debug_assert_eq!(
            self.domain, overlay.domain,
            "HostBlock::merge requires matching domains; caller must group first"
        );
        Self {
            domain: self.domain,
            methods: union_vecs(self.methods, overlay.methods),
            content_types: union_vecs(self.content_types, overlay.content_types),
            paths: union_vecs(self.paths, overlay.paths),
            max_request_bytes: match (self.max_request_bytes, overlay.max_request_bytes) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
            allow_credentials: union_vecs(self.allow_credentials, overlay.allow_credentials),
            contract_mode: overlay.contract_mode.or(self.contract_mode),
            upstream: overlay.upstream.or(self.upstream),
        }
    }

    /// Parse the `upstream` override. `None` means "dial the real
    /// destination"; an unparsable value is an error rather than a
    /// silent fallback, because falling back would send traffic meant
    /// for a local mock to the internet.
    pub fn upstream_target(&self) -> Result<Option<UpstreamTarget>, UpstreamParseError> {
        let Some(value) = self.upstream.as_deref() else {
            return Ok(None);
        };

        let invalid = || UpstreamParseError {
            domain: self.domain.clone(),
            value: value.to_string(),
        };

        let port = value.strip_prefix("loopback:").ok_or_else(invalid)?;
        let port: u16 = port.parse().map_err(|_| invalid())?;
        if port == 0 {
            return Err(invalid());
        }

        Ok(Some(UpstreamTarget::Loopback(port)))
    }
}

/// Mode for hosts that have no matching `[[host]]` entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ContractMode {
    /// Refuse any request to a host without a matching `[[host]]`
    /// entry. The default. Matches the project's default-deny
    /// posture (seccomp, network, mounts all default-deny).
    #[default]
    Strict,
    /// Allow requests to unknown hosts; emit a structured
    /// `unknown_host_contract` tracing event per request. Opt-in for
    /// prototyping / exploration workflows.
    Relaxed,
}

/// Union a list of `[[host]]` blocks by `domain`. Multiple recipes can
/// declare blocks for the same domain; the runtime sees one block per
/// FQDN with all field-level merges applied. Order within the output
/// is "first occurrence of each domain in the input."
pub fn merge_host_blocks(base: Vec<HostBlock>, overlay: Vec<HostBlock>) -> Vec<HostBlock> {
    use std::collections::HashMap;
    let mut indexed: Vec<HostBlock> = Vec::with_capacity(base.len() + overlay.len());
    let mut by_domain: HashMap<String, usize> = HashMap::new();
    for block in base.into_iter().chain(overlay.into_iter()) {
        match by_domain.get(&block.domain) {
            Some(&idx) => {
                let existing = std::mem::take(&mut indexed[idx]);
                indexed[idx] = existing.merge(block);
            }
            None => {
                by_domain.insert(block.domain.clone(), indexed.len());
                indexed.push(block);
            }
        }
    }
    indexed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_src: &str) -> Vec<HostBlock> {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            host: Vec<HostBlock>,
        }
        toml::from_str::<Wrapper>(toml_src).expect("parse").host
    }

    #[test]
    fn minimum_viable_block_parses() {
        let hosts = parse(
            r#"
            [[host]]
            domain = "static.example.com"
        "#,
        );
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].domain, "static.example.com");
        assert!(hosts[0].methods.is_empty());
        assert!(hosts[0].content_types.is_empty());
        assert!(hosts[0].allow_credentials.is_empty());
        assert!(hosts[0].max_request_bytes.is_none());
        assert!(hosts[0].contract_mode.is_none());
    }

    #[test]
    fn full_block_parses() {
        let hosts = parse(
            r#"
            [[host]]
            domain = "api.github.com"
            methods = ["GET", "POST"]
            content_types = ["application/json"]
            paths = ["/repos/"]
            max_request_bytes = 1048576
            allow_credentials = ["github_pat"]
            contract_mode = "relaxed"
        "#,
        );
        let h = &hosts[0];
        assert_eq!(h.methods, vec!["GET", "POST"]);
        assert_eq!(h.content_types, vec!["application/json"]);
        assert_eq!(h.paths, vec!["/repos/"]);
        assert_eq!(h.max_request_bytes, Some(1_048_576));
        assert_eq!(h.allow_credentials, vec!["github_pat"]);
        assert_eq!(h.contract_mode, Some(ContractMode::Relaxed));
    }

    #[test]
    fn unknown_field_fails_parse() {
        let err = toml::from_str::<HostBlock>(
            r#"
            domain = "x"
            mehtods = ["GET"]
        "#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected unknown-field error, got: {err}"
        );
    }

    #[test]
    fn contract_mode_default_is_strict() {
        assert_eq!(ContractMode::default(), ContractMode::Strict);
    }

    #[test]
    fn merge_unions_vec_fields() {
        let a = HostBlock {
            domain: "x".into(),
            methods: vec!["GET".into()],
            content_types: vec!["application/json".into()],
            allow_credentials: vec!["github_pat".into()],
            ..Default::default()
        };
        let b = HostBlock {
            domain: "x".into(),
            methods: vec!["POST".into(), "GET".into()],
            content_types: vec!["application/vnd.github+json".into()],
            allow_credentials: vec!["npm_token".into()],
            ..Default::default()
        };
        let m = a.merge(b);
        assert_eq!(m.methods, vec!["GET", "POST"]);
        assert_eq!(
            m.content_types,
            vec!["application/json", "application/vnd.github+json"]
        );
        assert_eq!(m.allow_credentials, vec!["github_pat", "npm_token"]);
    }

    #[test]
    fn merge_max_request_bytes_takes_max() {
        let a = HostBlock {
            domain: "x".into(),
            max_request_bytes: Some(1024),
            ..Default::default()
        };
        let b = HostBlock {
            domain: "x".into(),
            max_request_bytes: Some(2048),
            ..Default::default()
        };
        assert_eq!(a.clone().merge(b.clone()).max_request_bytes, Some(2048));
        assert_eq!(b.merge(a).max_request_bytes, Some(2048));
    }

    #[test]
    fn merge_contract_mode_is_last_some_wins() {
        let strict = HostBlock {
            domain: "x".into(),
            contract_mode: Some(ContractMode::Strict),
            ..Default::default()
        };
        let relaxed = HostBlock {
            domain: "x".into(),
            contract_mode: Some(ContractMode::Relaxed),
            ..Default::default()
        };
        let none = HostBlock {
            domain: "x".into(),
            contract_mode: None,
            ..Default::default()
        };
        assert_eq!(
            strict.clone().merge(relaxed.clone()).contract_mode,
            Some(ContractMode::Relaxed)
        );
        // None overlay preserves the base.
        assert_eq!(
            strict.clone().merge(none.clone()).contract_mode,
            Some(ContractMode::Strict)
        );
        // None base picks up the overlay.
        assert_eq!(
            none.merge(relaxed).contract_mode,
            Some(ContractMode::Relaxed)
        );
    }

    #[test]
    #[should_panic(expected = "matching domains")]
    fn merge_mismatched_domains_panics_in_debug() {
        let a = HostBlock {
            domain: "a".into(),
            ..Default::default()
        };
        let b = HostBlock {
            domain: "b".into(),
            ..Default::default()
        };
        let _ = a.merge(b);
    }

    #[test]
    fn merge_host_blocks_groups_by_domain() {
        let base = vec![
            HostBlock {
                domain: "github.com".into(),
                methods: vec!["GET".into()],
                ..Default::default()
            },
            HostBlock {
                domain: "registry.npmjs.org".into(),
                methods: vec!["GET".into()],
                ..Default::default()
            },
        ];
        let overlay = vec![
            HostBlock {
                domain: "github.com".into(),
                methods: vec!["POST".into()],
                ..Default::default()
            },
            HostBlock {
                domain: "pypi.org".into(),
                methods: vec!["GET".into()],
                ..Default::default()
            },
        ];
        let merged = merge_host_blocks(base, overlay);
        assert_eq!(merged.len(), 3);
        let github = merged.iter().find(|h| h.domain == "github.com").unwrap();
        assert_eq!(github.methods, vec!["GET", "POST"]);
        let npm = merged
            .iter()
            .find(|h| h.domain == "registry.npmjs.org")
            .unwrap();
        assert_eq!(npm.methods, vec!["GET"]);
        let pypi = merged.iter().find(|h| h.domain == "pypi.org").unwrap();
        assert_eq!(pypi.methods, vec!["GET"]);
    }
}
