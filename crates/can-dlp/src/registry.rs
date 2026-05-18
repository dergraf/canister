//! Detector registry — the single source of truth for every credential
//! pattern Canister knows how to detect.
//!
//! Adding a new detector is **one edit**: append a `DetectorDef` literal
//! to `REGISTRY` with at least one positive test vector. The pattern set,
//! scope table, canary generator, and registry-driven test suite all read
//! from this slice; no parallel updates required.
//!
//! Earlier versions kept the data in five places (a `DetectorId` enum, an
//! `as_str` match, an `all()` slice, a `PATTERNS` array by positional
//! index, a `pattern_to_detector` reverse map, and a
//! `builtin_home_domains` match) plus a hand-written test per detector.
//! The audit doc this refactor implements lives in the DLP plan PR notes
//! — search for "maintainability".

use crate::detectors::DetectorAction;

/// One detector's full definition.
pub struct DetectorDef {
    /// Snake-case identifier used in logs, events, recipe scope keys.
    /// Stable contract — changing this is a breaking change visible in
    /// recipes (`[dlp.scopes]` keys) and SIEM dashboards.
    pub id: &'static str,
    /// Regex source. `None` for detectors whose match is computed
    /// elsewhere (entropy-based, canary substring, …).
    pub regex: Option<&'static str>,
    /// Action when the detector fires outside its scope. Most are
    /// `Block`; `GenericHighEntropy` and similar low-precision detectors
    /// are `Warn`.
    pub default_action: DetectorAction,
    /// Built-in FQDN patterns where this credential is *expected* to
    /// flow. A finding at a host matching one of these is downgraded to
    /// a warning rather than a block. Wildcard patterns (`*.github.com`)
    /// are supported.
    pub home_domains: &'static [&'static str],
    /// How this detector interacts with the user-supplied
    /// `[dlp.scopes]` table.
    pub scope_policy: ScopePolicy,
    /// If `Some`, this detector has a corresponding canary that the
    /// sandbox injects as an environment variable. Used by both the
    /// canary generator and the response-direction scanner.
    pub canary: Option<CanarySpec>,
    /// Hand-curated test vectors. The registry-driven test driver
    /// asserts every vector here against the live pattern set. At
    /// minimum: one `OnlyMatch` (positive) and one `NoMatch` (near-miss
    /// negative). Reviewers should be able to see, from this slice
    /// alone, why the regex is correct.
    pub test_vectors: &'static [TestVector],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopePolicy {
    /// Block on every destination regardless of user config. Used for
    /// SSH/PKCS8 private keys, canary tokens, and Postgres URIs whose
    /// embedded credentials never have a legitimate egress path.
    AlwaysBlock,
    /// Allowed at `home_domains` plus any `[dlp.scopes].<id>` entries
    /// in the recipe. The default for "this token belongs at this
    /// service" detectors (GithubPat, NpmToken, AwsAccessKey, …).
    HomeAndScopes,
    /// Only allowed at explicit `[dlp.scopes].<id>` entries. No
    /// built-in home is meaningful — used for Bearer (any JWT) and
    /// GenericHighEntropy.
    ScopesOnly,
}

#[derive(Debug, Clone, Copy)]
pub struct CanarySpec {
    /// Environment variable name the sandbox injects into the worker.
    pub env_var: &'static str,
    /// Fixed prefix of the generated canary (must match the
    /// detector's regex prefix).
    pub prefix: &'static str,
    /// Number of random bytes appended after the prefix.
    pub random_len: usize,
    /// Alphabet used for the random part.
    pub charset: Charset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// `[A-Za-z0-9]` — 62 chars.
    Alnum,
    /// `[A-Z0-9]` — 36 chars. AWS access key format.
    UpperAlnum,
}

#[derive(Debug, Clone, Copy)]
pub struct TestVector {
    pub input: &'static str,
    pub expect: Expect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Only this detector should fire (cross-detector confusion guard).
    OnlyMatch,
    /// This detector should fire; others may also fire.
    Match,
    /// No detector should fire on this input (near-miss negative).
    NoMatch,
}

// ---------------------------------------------------------------------------
// Regex source constants
//
// Pulled out so each pattern has a greppable name. Updating a pattern is
// a one-line edit here.
// ---------------------------------------------------------------------------

const GITHUB_PAT_REGEX: &str =
    r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|gh[pousr]_[A-Za-z0-9]{36}";
const NPM_TOKEN_REGEX: &str = r"npm_[A-Za-z0-9]{36}";
const AWS_ACCESS_KEY_REGEX: &str = r"AKIA[A-Z0-9]{16}";
const BEARER_JWT_REGEX: &str =
    r"Bearer\s+eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}";
const SSH_PRIVATE_KEY_REGEX: &str = r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----";
const SLACK_TOKEN_REGEX: &str = r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}";
const OPENAI_KEY_REGEX: &str = r"sk-(?:proj-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{20,})";
const ANTHROPIC_KEY_REGEX: &str = r"sk-ant-(?:api|admin)[0-9]{1,3}-[A-Za-z0-9_\-]{20,}";
const GOOGLE_API_KEY_REGEX: &str = r"AIza[A-Za-z0-9_\-]{35}";
const STRIPE_KEY_REGEX: &str = r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}";
const POSTGRES_URI_REGEX: &str = r"postgres(?:ql)?://[^:/\s@]{1,128}:[^@/\s]{1,256}@[^/\s]+";
const PKCS8_PRIVATE_KEY_REGEX: &str = r"-----BEGIN PRIVATE KEY-----";

// ---------------------------------------------------------------------------
// The registry. One entry per detector. Adding a detector below is the
// only edit required to teach the whole pipeline.
// ---------------------------------------------------------------------------

pub const REGISTRY: &[DetectorDef] = &[
    DetectorDef {
        id: "github_pat",
        regex: Some(GITHUB_PAT_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &["github.com", "*.github.com"],
        scope_policy: ScopePolicy::HomeAndScopes,
        canary: Some(CanarySpec {
            env_var: "CANISTER_CANARY_GITHUB_PAT",
            prefix: "ghp_",
            random_len: 36,
            charset: Charset::Alnum,
        }),
        test_vectors: &[
            TestVector {
                input: "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "ghs_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                // Fine-grained PAT shape: 22 + 1 + 59 = 82 after `github_pat_`.
                input: "github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "ghp_short",
                expect: Expect::NoMatch,
            },
            TestVector {
                input: "this is not a github pat",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "npm_token",
        regex: Some(NPM_TOKEN_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &["registry.npmjs.org"],
        scope_policy: ScopePolicy::HomeAndScopes,
        canary: Some(CanarySpec {
            env_var: "CANISTER_CANARY_NPM_TOKEN",
            prefix: "npm_",
            random_len: 36,
            charset: Charset::Alnum,
        }),
        test_vectors: &[
            TestVector {
                input: "npm_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "npm_short",
                expect: Expect::NoMatch,
            },
            TestVector {
                input: "npmpkg_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "aws_access_key",
        regex: Some(AWS_ACCESS_KEY_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &["*.amazonaws.com"],
        scope_policy: ScopePolicy::HomeAndScopes,
        canary: Some(CanarySpec {
            env_var: "CANISTER_CANARY_AWS_ACCESS_KEY",
            prefix: "AKIA",
            random_len: 16,
            charset: Charset::UpperAlnum,
        }),
        test_vectors: &[
            TestVector {
                input: "AKIA1234567890ABCDEF",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "AKIBNOTANACCESSKEYAB",
                expect: Expect::NoMatch,
            },
            TestVector {
                input: "AKIAshort",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "bearer_token",
        regex: Some(BEARER_JWT_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &[],
        scope_policy: ScopePolicy::ScopesOnly,
        canary: None,
        test_vectors: &[
            TestVector {
                input: "Bearer eyJhaaaaaaaaaaaaaaaaaa.eyJbbbbbbbbbbbbbbbbbb.cccccccccccccccccccc",
                expect: Expect::OnlyMatch,
            },
            // The pre-tightening loose form must no longer fire (F12 in
            // the DLP plan). Bearer + 40 opaque chars is not a JWT shape.
            TestVector {
                input: "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::NoMatch,
            },
            TestVector {
                input: "Bearer short",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "ssh_private_key",
        regex: Some(SSH_PRIVATE_KEY_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &[],
        scope_policy: ScopePolicy::AlwaysBlock,
        canary: None,
        test_vectors: &[
            TestVector {
                input: "-----BEGIN RSA PRIVATE KEY-----",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "-----BEGIN OPENSSH PRIVATE KEY-----",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "-----BEGIN EC PRIVATE KEY-----",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "-----BEGIN CERTIFICATE-----",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "slack_token",
        regex: Some(SLACK_TOKEN_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &["*.slack.com"],
        scope_policy: ScopePolicy::HomeAndScopes,
        canary: None,
        test_vectors: &[
            TestVector {
                input: "xoxb-111111111111-222222222222-AAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "xoxz-111111111111-222222222222-AAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        // GenericHighEntropy is special: it has no regex (entropy-based
        // findings are produced by the body/entropy budget path). It's
        // listed here so callers can look up its scope policy via the
        // registry like every other detector.
        id: "generic_high_entropy",
        regex: None,
        default_action: DetectorAction::Warn,
        home_domains: &[],
        scope_policy: ScopePolicy::ScopesOnly,
        canary: None,
        test_vectors: &[],
    },
    DetectorDef {
        // CanaryToken doesn't have a regex either — it matches via
        // substring against the per-session canary values. Registered so
        // scope policy lookups stay uniform.
        id: "canary_token",
        regex: None,
        default_action: DetectorAction::Block,
        home_domains: &[],
        scope_policy: ScopePolicy::AlwaysBlock,
        canary: None,
        test_vectors: &[],
    },
    DetectorDef {
        id: "openai_key",
        regex: Some(OPENAI_KEY_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &["api.openai.com"],
        scope_policy: ScopePolicy::HomeAndScopes,
        canary: None,
        test_vectors: &[
            TestVector {
                input: "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                // Project-key variant.
                input: "sk-proj-Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_Ab1_",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "sk-tooshort",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "anthropic_key",
        regex: Some(ANTHROPIC_KEY_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &["api.anthropic.com"],
        scope_policy: ScopePolicy::HomeAndScopes,
        canary: None,
        test_vectors: &[
            TestVector {
                input: "sk-ant-api03-Az_-Az_-Az_-Az_-Az_-Az_-Az_-Az_-Az_-Az_-",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "sk-ant-admin01-Az_-Az_-Az_-Az_-Az_-Az_-",
                expect: Expect::OnlyMatch,
            },
            // Cross-detector confusion guard: this looks like it could
            // be an OpenAI legacy key (`sk-…`), but the hyphens after
            // `ant-` exclude it from the OpenAI charset. OnlyMatch
            // pins that.
            TestVector {
                input: "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "sk-ant-api-shortenough",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "google_api_key",
        regex: Some(GOOGLE_API_KEY_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &[
            "googleapis.com",
            "*.googleapis.com",
            "generativelanguage.googleapis.com",
        ],
        scope_policy: ScopePolicy::HomeAndScopes,
        canary: None,
        test_vectors: &[
            TestVector {
                input: "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "AIzashort",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "stripe_key",
        regex: Some(STRIPE_KEY_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &["api.stripe.com"],
        scope_policy: ScopePolicy::HomeAndScopes,
        canary: None,
        test_vectors: &[
            TestVector {
                input: "sk_live_AAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "sk_test_ZZZZZZZZZZZZZZZZZZZZZZZZ",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "rk_live_AAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "sk_prod_AAAAAAAAAAAAAAAAAAAAAAAA",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "postgres_uri",
        regex: Some(POSTGRES_URI_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &[],
        scope_policy: ScopePolicy::AlwaysBlock,
        canary: None,
        test_vectors: &[
            TestVector {
                input: "postgresql://admin:hunter2@db.internal.example.com:5432/prod",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "postgres://user:secret@localhost/db",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                // No `user:pass@` segment — just a connection string,
                // no secret. Must not fire.
                input: "postgresql://db.internal:5432/prod",
                expect: Expect::NoMatch,
            },
        ],
    },
    DetectorDef {
        id: "pkcs8_private_key",
        regex: Some(PKCS8_PRIVATE_KEY_REGEX),
        default_action: DetectorAction::Block,
        home_domains: &[],
        scope_policy: ScopePolicy::AlwaysBlock,
        canary: None,
        test_vectors: &[
            TestVector {
                input: "-----BEGIN PRIVATE KEY-----",
                expect: Expect::OnlyMatch,
            },
            TestVector {
                input: "-----BEGIN PUBLIC KEY-----",
                expect: Expect::NoMatch,
            },
        ],
    },
];

/// Look up a detector definition by id. Returns `None` for unknown ids;
/// every id emitted by the live `PatternSet` is guaranteed to be in the
/// registry, so a lookup should only fail in tests that construct ids
/// from string literals.
pub fn lookup(id: &str) -> Option<&'static DetectorDef> {
    REGISTRY.iter().find(|d| d.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn registry_ids_are_unique() {
        let mut seen = HashSet::new();
        for d in REGISTRY {
            assert!(seen.insert(d.id), "duplicate detector id: {}", d.id);
        }
    }

    #[test]
    fn registry_regex_patterns_compile() {
        // If any regex is malformed, PatternSet::new() will also fail,
        // but a per-pattern test gives a far clearer error message than
        // RegexSet's bulk failure.
        for d in REGISTRY {
            if let Some(pat) = d.regex {
                assert!(
                    regex::Regex::new(pat).is_ok(),
                    "detector {} regex does not compile: {pat}",
                    d.id
                );
            }
        }
    }

    #[test]
    fn every_regex_detector_has_at_least_one_vector() {
        for d in REGISTRY {
            if d.regex.is_some() {
                assert!(
                    !d.test_vectors.is_empty(),
                    "detector {} has a regex but no test_vectors — \
                     add at least one OnlyMatch and one NoMatch",
                    d.id
                );
                let has_pos = d
                    .test_vectors
                    .iter()
                    .any(|v| matches!(v.expect, Expect::OnlyMatch | Expect::Match));
                let has_neg = d.test_vectors.iter().any(|v| v.expect == Expect::NoMatch);
                assert!(has_pos, "detector {} has no positive test vector", d.id);
                assert!(has_neg, "detector {} has no negative test vector", d.id);
            }
        }
    }

    #[test]
    fn canary_prefix_matches_detector_regex() {
        // A canary's prefix must be matchable by the detector's regex,
        // otherwise the canary won't fire its own detector.
        for d in REGISTRY {
            let (Some(spec), Some(pat)) = (d.canary, d.regex) else {
                continue;
            };
            let re = regex::Regex::new(pat).unwrap();
            // Build a plausible canary value: prefix + a run of valid
            // chars from the charset.
            let filler = match spec.charset {
                Charset::Alnum => "A",
                Charset::UpperAlnum => "A",
            };
            let sample = format!("{}{}", spec.prefix, filler.repeat(spec.random_len));
            assert!(
                re.is_match(&sample),
                "detector {}: canary sample {sample:?} doesn't match its own regex",
                d.id
            );
        }
    }
}
