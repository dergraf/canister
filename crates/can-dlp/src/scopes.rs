use std::collections::HashMap;

use crate::detectors::DetectorId;
use crate::registry::{REGISTRY, ScopePolicy};

/// Match `host` against an FQDN pattern. Supports the `*.example.com`
/// leading-wildcard form (used by built-in home domains) and bare
/// equality / subdomain matching.
pub fn domain_matches(host: &str, pattern: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let pattern = pattern.to_ascii_lowercase();
    if host == pattern {
        return true;
    }
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        return host.ends_with(suffix);
    }
    host.ends_with(&format!(".{pattern}"))
}

/// Per-detector scope table, derived from the registry at construction
/// time and merged with any `[dlp.scopes]` entries from the recipe.
///
/// The construction logic is uniform — no per-detector special cases.
/// Every per-detector knob lives in [`crate::registry::REGISTRY`].
pub struct DlpScopes {
    /// `id → domains`. For `ScopePolicy::HomeAndScopes` detectors,
    /// `domains` is the union of built-in home domains and any
    /// user-supplied scopes for that id. For `ScopePolicy::ScopesOnly`
    /// the user-supplied list is the only source. `AlwaysBlock`
    /// detectors don't have an entry — lookups for them return `false`
    /// regardless.
    domains: HashMap<&'static str, Vec<String>>,
}

impl DlpScopes {
    /// Build the scope table by walking the registry. `user_scopes`
    /// keys are detector ids (`github_pat`, `bearer_token`, …); values
    /// are FQDN patterns from the recipe's `[dlp.scopes]` table.
    pub fn new(user_scopes: &HashMap<String, Vec<String>>) -> Self {
        let mut domains: HashMap<&'static str, Vec<String>> = HashMap::new();

        for def in REGISTRY {
            let mut entry: Vec<String> = match def.scope_policy {
                ScopePolicy::AlwaysBlock => Vec::new(),
                ScopePolicy::HomeAndScopes => {
                    def.home_domains.iter().map(|s| s.to_string()).collect()
                }
                ScopePolicy::ScopesOnly => Vec::new(),
            };

            if let Some(extras) = user_scopes.get(def.id) {
                for extra in extras {
                    if !entry.contains(extra) {
                        entry.push(extra.clone());
                    }
                }
            }
            domains.insert(def.id, entry);
        }

        Self { domains }
    }

    pub fn is_allowed(&self, detector: DetectorId, destination_host: &str) -> bool {
        // `AlwaysBlock` is encoded as "registered, but with an empty
        // domain list that the user can never extend." We enforce that
        // by checking the policy directly from the registry before
        // consulting the merged list, so a user who adds
        // `[dlp.scopes].ssh_private_key = ["..."]` cannot whitelist
        // SSH key egress.
        let policy = crate::registry::lookup(detector.as_str())
            .map(|d| d.scope_policy)
            .unwrap_or(ScopePolicy::AlwaysBlock);
        if matches!(policy, ScopePolicy::AlwaysBlock) {
            return false;
        }

        let home = self
            .domains
            .get(detector.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        home.iter().any(|d| domain_matches(destination_host, d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn scopes() -> DlpScopes {
        DlpScopes::new(&HashMap::new())
    }

    // --- Registry-derived properties: rather than naming every
    // detector by hand, walk the registry and assert the documented
    // policy. Adding a detector with a new policy automatically extends
    // coverage. ---

    #[test]
    fn always_block_detectors_block_everywhere() {
        let s = scopes();
        for def in REGISTRY {
            if !matches!(def.scope_policy, ScopePolicy::AlwaysBlock) {
                continue;
            }
            let id = DetectorId::new(def.id);
            assert!(
                !s.is_allowed(id, "github.com"),
                "[{}] should always block, allowed github.com",
                def.id
            );
            assert!(
                !s.is_allowed(id, "evil.example.com"),
                "[{}] should always block, allowed evil.example.com",
                def.id
            );
        }
    }

    #[test]
    fn home_and_scopes_allow_their_home_domains() {
        let s = scopes();
        for def in REGISTRY {
            if !matches!(def.scope_policy, ScopePolicy::HomeAndScopes) {
                continue;
            }
            let id = DetectorId::new(def.id);
            for home in def.home_domains {
                // Wildcard patterns can't be directly asked about — pick
                // a concrete instance instead.
                let probe = if let Some(stripped) = home.strip_prefix("*.") {
                    format!("foo.{stripped}")
                } else {
                    home.to_string()
                };
                assert!(
                    s.is_allowed(id, &probe),
                    "[{}] {:?} should be allowed at home domain {}",
                    def.id,
                    probe,
                    home,
                );
            }
        }
    }

    #[test]
    fn home_and_scopes_block_off_home() {
        let s = scopes();
        for def in REGISTRY {
            if !matches!(def.scope_policy, ScopePolicy::HomeAndScopes) {
                continue;
            }
            let id = DetectorId::new(def.id);
            assert!(
                !s.is_allowed(id, "absolutely-not-a-home.evil"),
                "[{}] should block at random destination",
                def.id
            );
        }
    }

    #[test]
    fn scopes_only_requires_explicit_entry() {
        let s = scopes();
        for def in REGISTRY {
            if !matches!(def.scope_policy, ScopePolicy::ScopesOnly) {
                continue;
            }
            let id = DetectorId::new(def.id);
            assert!(
                !s.is_allowed(id, "api.example.com"),
                "[{}] should require explicit [dlp.scopes] entry, but was allowed",
                def.id,
            );
        }
    }

    #[test]
    fn scopes_only_allowed_after_user_entry() {
        for def in REGISTRY {
            if !matches!(def.scope_policy, ScopePolicy::ScopesOnly) {
                continue;
            }
            let mut user = HashMap::new();
            user.insert(def.id.to_string(), vec!["api.example.com".to_string()]);
            let s = DlpScopes::new(&user);
            let id = DetectorId::new(def.id);
            assert!(
                s.is_allowed(id, "api.example.com"),
                "[{}] should be allowed at explicit scope, but wasn't",
                def.id,
            );
            assert!(
                !s.is_allowed(id, "evil.example.com"),
                "[{}] should still block at unlisted destination",
                def.id,
            );
        }
    }

    #[test]
    fn user_scopes_cannot_override_always_block() {
        // Try to allow SshPrivateKey at `attacker.com` via user scopes —
        // must be refused.
        let mut user = HashMap::new();
        user.insert(
            "ssh_private_key".to_string(),
            vec!["attacker.com".to_string()],
        );
        let s = DlpScopes::new(&user);
        assert!(!s.is_allowed(DetectorId::new("ssh_private_key"), "attacker.com"));
    }

    #[test]
    fn user_scopes_extend_home() {
        let mut user = HashMap::new();
        user.insert(
            "github_pat".to_string(),
            vec!["github.corp.example.com".to_string()],
        );
        let s = DlpScopes::new(&user);
        assert!(s.is_allowed(DetectorId::new("github_pat"), "github.com"));
        assert!(s.is_allowed(DetectorId::new("github_pat"), "github.corp.example.com"));
        assert!(!s.is_allowed(DetectorId::new("github_pat"), "evil.com"));
    }

    // --- domain_matches helper (unchanged behaviour, kept for clarity). ---

    #[test]
    fn domain_matches_exact() {
        assert!(domain_matches("github.com", "github.com"));
        assert!(!domain_matches("evil.com", "github.com"));
    }

    #[test]
    fn domain_matches_subdomain() {
        assert!(domain_matches("api.github.com", "github.com"));
        assert!(!domain_matches("notgithub.com", "github.com"));
    }

    #[test]
    fn domain_matches_wildcard() {
        assert!(domain_matches("hooks.slack.com", "*.slack.com"));
        assert!(domain_matches("api.slack.com", "*.slack.com"));
        assert!(!domain_matches("slack.com", "*.slack.com"));
    }

    #[test]
    fn domain_matches_case_insensitive() {
        assert!(domain_matches("GitHub.COM", "github.com"));
        assert!(domain_matches("API.GitHub.Com", "*.github.com"));
    }
}
