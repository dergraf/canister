//! Per-destination egress contract enforcement.
//!
//! See `docs/adr/0007-per-destination-egress-contracts.md`. The
//! contract gate runs in `handle_inner_request` between the policy
//! gate (connect permission) and the DLP scanner. If a request
//! doesn't fit the shape its destination contract allows, it's
//! refused **before** any decode chain runs — closing the structural
//! attack class where an attacker base64-wraps a credential and
//! hopes one decoder gives up.

use can_policy::config::{ContractMode, HostBlock};

/// The shape of an in-flight request relevant to contract checking.
/// All fields except `method` and `path` are `Option` because they
/// aren't always populated by the time we run the gate (body size
/// is known only after buffering; content type may be absent).
#[derive(Debug, Clone)]
pub struct RequestShape<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub content_type: Option<&'a str>,
    pub body_size: Option<u64>,
}

/// Why a request was refused. Each variant carries enough detail to
/// produce an actionable error response — the `[[host]]` patch the
/// user can paste into their `canister.toml` to allow this exact
/// shape.
#[derive(Debug, Clone)]
pub enum ContractViolation {
    /// `Strict` mode + no `[[host]]` block for this FQDN.
    UnknownHost,
    /// Method not in the host's `methods` allow-list.
    DisallowedMethod {
        method: String,
        allowed: Vec<String>,
    },
    /// `Content-Type` not in the host's `content_types` allow-list.
    DisallowedContentType {
        content_type: String,
        allowed: Vec<String>,
    },
    /// Request path doesn't match any entry in the host's `paths`
    /// allow-list.
    DisallowedPath { path: String, allowed: Vec<String> },
    /// Body size exceeds the per-host cap.
    OversizeBody { size: u64, limit: u64 },
}

impl ContractViolation {
    /// Short reason code, suitable for the `x-canister-error` header.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::UnknownHost => "unknown-host",
            Self::DisallowedMethod { .. } => "method-not-allowed",
            Self::DisallowedContentType { .. } => "content-type-not-allowed",
            Self::DisallowedPath { .. } => "path-not-allowed",
            Self::OversizeBody { .. } => "body-too-large",
        }
    }
}

/// Resolved contract table for a proxy session. Built once at
/// `ProxyServer::new` time from the `[[host]]` blocks in the
/// effective recipe; consulted on every request.
#[derive(Debug, Clone, Default)]
pub struct ContractTable {
    blocks: Vec<HostBlock>,
    default_mode: ContractMode,
}

impl ContractTable {
    pub fn new(blocks: Vec<HostBlock>, default_mode: ContractMode) -> Self {
        Self {
            blocks,
            default_mode,
        }
    }

    /// Find the `[[host]]` block matching `host`. Most-specific
    /// match wins — `api.github.com` beats `*.github.com` beats
    /// `*.com`. Matching is case-insensitive.
    pub fn lookup(&self, host: &str) -> Option<&HostBlock> {
        let host_lc = host.to_ascii_lowercase();
        let mut best: Option<(&HostBlock, usize)> = None;
        for b in &self.blocks {
            if let Some(score) = match_score(&host_lc, &b.domain) {
                match best {
                    Some((_, best_score)) if best_score >= score => {}
                    _ => best = Some((b, score)),
                }
            }
        }
        best.map(|(b, _)| b)
    }

    /// Resolved contract mode for `host`. Per-block override wins
    /// over the global default; unknown hosts inherit the global
    /// default (so a `Strict` recipe refuses unknown hosts, a
    /// `Relaxed` recipe lets them through with a tracing event).
    pub fn mode_for(&self, host: &str) -> ContractMode {
        self.lookup(host)
            .and_then(|b| b.contract_mode)
            .unwrap_or(self.default_mode)
    }

    /// Check a request shape against the resolved contract. Returns
    /// `Some(violation)` if the request must be refused, `None`
    /// otherwise.
    pub fn check(&self, host: &str, req: &RequestShape<'_>) -> Option<ContractViolation> {
        let block = match self.lookup(host) {
            Some(b) => b,
            None => {
                // Per-host mode can't override anything without a
                // block to attach the override to, so the global
                // mode decides.
                return match self.default_mode {
                    ContractMode::Strict => Some(ContractViolation::UnknownHost),
                    ContractMode::Relaxed => None,
                };
            }
        };

        if !block.methods.is_empty()
            && !block
                .methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(req.method))
        {
            return Some(ContractViolation::DisallowedMethod {
                method: req.method.to_string(),
                allowed: block.methods.clone(),
            });
        }

        if !block.content_types.is_empty() {
            // Compare just the mime/subtype portion, ignoring `;
            // charset=utf-8` parameters.
            let req_ct = req.content_type.unwrap_or("");
            let req_mime = req_ct
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            // A request with no Content-Type is allowed iff the
            // block allows the empty string, which it can't; emit a
            // violation pointing at the mismatch.
            if !block
                .content_types
                .iter()
                .any(|c| c.to_ascii_lowercase() == req_mime)
            {
                return Some(ContractViolation::DisallowedContentType {
                    content_type: req_ct.to_string(),
                    allowed: block.content_types.clone(),
                });
            }
        }

        if !block.paths.is_empty() && !block.paths.iter().any(|p| req.path.starts_with(p.as_str()))
        {
            return Some(ContractViolation::DisallowedPath {
                path: req.path.to_string(),
                allowed: block.paths.clone(),
            });
        }

        if let (Some(limit), Some(size)) = (block.max_request_bytes, req.body_size) {
            if size > limit {
                return Some(ContractViolation::OversizeBody { size, limit });
            }
        }

        None
    }
}

/// Score how well `pattern` matches `host`. `None` = no match.
/// Higher score = more specific. Exact match > wildcard > none.
fn match_score(host: &str, pattern: &str) -> Option<usize> {
    let pattern = pattern.to_ascii_lowercase();
    if pattern == host {
        // Exact equality outranks every wildcard.
        return Some(usize::MAX);
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if host.ends_with(suffix) && host.len() > suffix.len() {
            // The boundary char must be `.` so `*.github.com`
            // doesn't match `notgithub.com`.
            let prefix_len = host.len() - suffix.len();
            if host.as_bytes()[prefix_len - 1] == b'.' {
                return Some(suffix.len());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(domain: &str) -> HostBlock {
        HostBlock {
            domain: domain.to_string(),
            ..Default::default()
        }
    }

    fn shape<'a>(method: &'a str, path: &'a str) -> RequestShape<'a> {
        RequestShape {
            method,
            path,
            content_type: None,
            body_size: None,
        }
    }

    #[test]
    fn unknown_host_strict_refuses() {
        let t = ContractTable::new(vec![block("github.com")], ContractMode::Strict);
        let v = t.check("evil.example.com", &shape("GET", "/"));
        assert!(matches!(v, Some(ContractViolation::UnknownHost)));
    }

    #[test]
    fn unknown_host_relaxed_allows() {
        let t = ContractTable::new(vec![block("github.com")], ContractMode::Relaxed);
        assert!(t.check("evil.example.com", &shape("GET", "/")).is_none());
    }

    #[test]
    fn exact_match_beats_wildcard() {
        let t = ContractTable::new(
            vec![
                HostBlock {
                    domain: "*.github.com".to_string(),
                    methods: vec!["GET".to_string()],
                    ..Default::default()
                },
                HostBlock {
                    domain: "api.github.com".to_string(),
                    methods: vec!["POST".to_string()],
                    ..Default::default()
                },
            ],
            ContractMode::Strict,
        );
        // Exact match for api.github.com permits POST but not GET.
        assert!(matches!(
            t.check("api.github.com", &shape("GET", "/")),
            Some(ContractViolation::DisallowedMethod { .. })
        ));
        assert!(t.check("api.github.com", &shape("POST", "/")).is_none());
        // Wildcard catches other subdomains and only permits GET.
        assert!(t.check("uploads.github.com", &shape("GET", "/")).is_none());
        assert!(matches!(
            t.check("uploads.github.com", &shape("POST", "/")),
            Some(ContractViolation::DisallowedMethod { .. })
        ));
    }

    #[test]
    fn wildcard_does_not_match_bare_domain() {
        let t = ContractTable::new(vec![block("*.github.com")], ContractMode::Strict);
        assert!(matches!(
            t.check("github.com", &shape("GET", "/")),
            Some(ContractViolation::UnknownHost)
        ));
    }

    #[test]
    fn wildcard_does_not_match_substring_suffix() {
        let t = ContractTable::new(vec![block("*.github.com")], ContractMode::Strict);
        // notgithub.com ends with "github.com" but the boundary
        // char isn't a dot — must not match.
        assert!(matches!(
            t.check("notgithub.com", &shape("GET", "/")),
            Some(ContractViolation::UnknownHost)
        ));
    }

    #[test]
    fn methods_check_case_insensitive() {
        let t = ContractTable::new(
            vec![HostBlock {
                domain: "api.example.com".into(),
                methods: vec!["GET".into(), "POST".into()],
                ..Default::default()
            }],
            ContractMode::Strict,
        );
        assert!(t.check("api.example.com", &shape("get", "/")).is_none());
        assert!(t.check("api.example.com", &shape("POST", "/")).is_none());
        assert!(matches!(
            t.check("api.example.com", &shape("DELETE", "/")),
            Some(ContractViolation::DisallowedMethod { .. })
        ));
    }

    #[test]
    fn content_type_check_ignores_charset_parameter() {
        let t = ContractTable::new(
            vec![HostBlock {
                domain: "api.example.com".into(),
                content_types: vec!["application/json".into()],
                ..Default::default()
            }],
            ContractMode::Strict,
        );
        let mut s = shape("POST", "/");
        s.content_type = Some("application/json; charset=utf-8");
        assert!(t.check("api.example.com", &s).is_none());
        s.content_type = Some("image/png");
        assert!(matches!(
            t.check("api.example.com", &s),
            Some(ContractViolation::DisallowedContentType { .. })
        ));
    }

    #[test]
    fn path_check_matches_prefix() {
        let t = ContractTable::new(
            vec![HostBlock {
                domain: "api.github.com".into(),
                paths: vec!["/repos/".into(), "/user/".into()],
                ..Default::default()
            }],
            ContractMode::Strict,
        );
        assert!(
            t.check("api.github.com", &shape("GET", "/repos/foo"))
                .is_none()
        );
        assert!(matches!(
            t.check("api.github.com", &shape("GET", "/admin")),
            Some(ContractViolation::DisallowedPath { .. })
        ));
    }

    #[test]
    fn body_size_check() {
        let t = ContractTable::new(
            vec![HostBlock {
                domain: "api.example.com".into(),
                max_request_bytes: Some(1024),
                ..Default::default()
            }],
            ContractMode::Strict,
        );
        let mut s = shape("POST", "/");
        s.body_size = Some(512);
        assert!(t.check("api.example.com", &s).is_none());
        s.body_size = Some(2048);
        assert!(matches!(
            t.check("api.example.com", &s),
            Some(ContractViolation::OversizeBody { .. })
        ));
    }

    #[test]
    fn per_host_mode_override_wins_over_global() {
        let t = ContractTable::new(
            vec![HostBlock {
                domain: "weird.internal".into(),
                contract_mode: Some(ContractMode::Relaxed),
                methods: vec!["GET".into()], // would refuse POST in strict
                ..Default::default()
            }],
            ContractMode::Strict,
        );
        // The mode_for query returns Relaxed for weird.internal.
        assert_eq!(t.mode_for("weird.internal"), ContractMode::Relaxed);
        // But the request still gates on the block's own methods —
        // contract_mode only affects the unknown-host decision, not
        // the field-level checks once a block is matched.
        assert!(matches!(
            t.check("weird.internal", &shape("POST", "/")),
            Some(ContractViolation::DisallowedMethod { .. })
        ));
    }

    #[test]
    fn empty_block_is_permissive() {
        let t = ContractTable::new(vec![block("static.example.com")], ContractMode::Strict);
        let mut s = shape("DELETE", "/anywhere");
        s.content_type = Some("application/x-custom");
        s.body_size = Some(u64::MAX);
        assert!(t.check("static.example.com", &s).is_none());
    }
}
