//! Compiled regex pattern set + the small `DetectorId` newtype that
//! identifies detectors across the rest of the crate.
//!
//! All data — the regex sources, default actions, ids — lives in
//! [`crate::registry::REGISTRY`]. This module is just the runtime glue:
//! it walks the registry at construction time to build a [`RegexSet`]
//! and to memoise an index → id mapping.

use std::fmt;

use regex::RegexSet;

use crate::error::DlpError;
use crate::registry::{REGISTRY, lookup};

/// Stable identifier for a detector. Comparisons are on the underlying
/// snake-case id (`"github_pat"`, `"canary_token"`, …). Constructed via
/// `DetectorId::new` from a static string literal that must exist in the
/// registry, or returned by [`PatternSet::scan`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DetectorId(&'static str);

impl DetectorId {
    /// Wrap a registry id. The string must outlive the program (typical
    /// callers pass a literal from the registry).
    pub const fn new(id: &'static str) -> Self {
        Self(id)
    }

    /// Snake-case identifier, as it appears in recipe scope keys,
    /// response headers, and JSON events.
    pub fn as_str(&self) -> &'static str {
        self.0
    }

    /// Default action when this detector fires outside its scope. Looks
    /// up the registry; falls back to `Block` for ids that aren't
    /// registered (defensive — shouldn't happen in production).
    pub fn default_action(&self) -> DetectorAction {
        lookup(self.0)
            .map(|d| d.default_action)
            .unwrap_or(DetectorAction::Block)
    }
}

impl fmt::Display for DetectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl fmt::Debug for DetectorId {
    // Emit the bare id rather than `DetectorId("github_pat")` — log
    // lines and JSON events are easier to read this way.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorAction {
    Block,
    Warn,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub detector: DetectorId,
    pub matched_text: String,
}

/// Compiled set of every regex-bearing detector in the registry, plus an
/// optional per-session canary substring list. Built once at session
/// start by [`PatternSet::new`] (or [`PatternSet::with_canaries`]).
pub struct PatternSet {
    regex_set: RegexSet,
    /// Parallel to `regex_set`: index `i` matched ⇒ detector
    /// `index_to_id[i]` fired. Built at construction time from the
    /// registry so we never compute an index→id mapping by hand.
    index_to_id: Vec<DetectorId>,
    /// Per-detector compiled regex, for `find()` to recover the exact
    /// matched substring. Same length / order as `index_to_id`.
    per_detector_regex: Vec<regex::Regex>,
    canary_values: Vec<String>,
}

impl PatternSet {
    pub fn new() -> Result<Self, DlpError> {
        Self::build(Vec::new())
    }

    pub fn with_canaries(canaries: Vec<String>) -> Result<Self, DlpError> {
        Self::build(canaries)
    }

    fn build(canaries: Vec<String>) -> Result<Self, DlpError> {
        let mut patterns: Vec<&'static str> = Vec::with_capacity(REGISTRY.len());
        let mut index_to_id: Vec<DetectorId> = Vec::with_capacity(REGISTRY.len());
        let mut per_detector_regex: Vec<regex::Regex> = Vec::with_capacity(REGISTRY.len());

        for def in REGISTRY {
            if let Some(pat) = def.regex {
                patterns.push(pat);
                index_to_id.push(DetectorId::new(def.id));
                per_detector_regex.push(regex::Regex::new(pat)?);
            }
        }

        let regex_set = RegexSet::new(&patterns)?;
        Ok(Self {
            regex_set,
            index_to_id,
            per_detector_regex,
            canary_values: canaries,
        })
    }

    pub fn scan(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Canary substring match runs first so a canary-shaped value
        // gets its own detector id even when it also looks like a
        // structurally-valid GitHub PAT.
        for canary in &self.canary_values {
            if text.contains(canary.as_str()) {
                findings.push(Finding {
                    detector: DetectorId::new(crate::ids::CANARY_TOKEN),
                    matched_text: canary.clone(),
                });
            }
        }

        for index in self.regex_set.matches(text) {
            let detector = self.index_to_id[index];
            let matched_text = self.per_detector_regex[index]
                .find(text)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            findings.push(Finding {
                detector,
                matched_text,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{Expect, REGISTRY};

    fn ps() -> PatternSet {
        PatternSet::new().unwrap()
    }

    // --- The registry-driven driver. One test, every detector, every
    // hand-curated vector. ---

    #[test]
    fn registry_test_vectors_all_pass() {
        let ps = ps();
        for def in REGISTRY {
            for tv in def.test_vectors {
                let findings = ps.scan(tv.input);
                let own = findings
                    .iter()
                    .filter(|f| f.detector.as_str() == def.id)
                    .count();
                let foreign: Vec<&str> = findings
                    .iter()
                    .filter(|f| f.detector.as_str() != def.id)
                    .map(|f| f.detector.as_str())
                    .collect();

                match tv.expect {
                    Expect::NoMatch => assert!(
                        findings.is_empty(),
                        "[{}] {:?} should not match anything, got {:?}",
                        def.id,
                        tv.input,
                        findings
                            .iter()
                            .map(|f| f.detector.as_str())
                            .collect::<Vec<_>>(),
                    ),
                    Expect::Match => assert!(
                        own >= 1,
                        "[{}] {:?} should fire this detector (got {} own, {} foreign)",
                        def.id,
                        tv.input,
                        own,
                        foreign.len(),
                    ),
                    Expect::OnlyMatch => {
                        assert!(
                            own >= 1,
                            "[{}] {:?} should fire this detector",
                            def.id,
                            tv.input
                        );
                        assert!(
                            foreign.is_empty(),
                            "[{}] {:?} also fired {:?} — cross-detector confusion",
                            def.id,
                            tv.input,
                            foreign,
                        );
                    }
                }
            }
        }
    }

    // --- Encoded-variant survival. Every OnlyMatch vector is encoded
    // through base64 / hex / percent and re-fed into the scanner; the
    // detector must still fire after decode_layers unwraps the
    // encoding. ---

    #[test]
    fn registry_encoded_variants_caught() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;

        let scanner = crate::scanner::DlpScanner::new(
            Vec::new(),
            &std::collections::HashMap::new(),
            32,
            true,
            false,
        )
        .unwrap();
        for def in REGISTRY {
            for tv in def.test_vectors {
                if tv.expect != Expect::OnlyMatch {
                    continue;
                }
                // Base64.
                let b64 = STANDARD.encode(tv.input.as_bytes());
                let verdicts = scanner.scan_body(b64.as_bytes(), None, "evil.example.com");
                assert!(
                    verdicts.iter().any(|v| v.detector.as_str() == def.id),
                    "[{}] base64({:?}) should still be caught",
                    def.id,
                    tv.input,
                );
                // Hex.
                let hex: String = tv
                    .input
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let verdicts = scanner.scan_body(hex.as_bytes(), None, "evil.example.com");
                assert!(
                    verdicts.iter().any(|v| v.detector.as_str() == def.id),
                    "[{}] hex({:?}) should still be caught",
                    def.id,
                    tv.input,
                );
            }
        }
    }

    // --- Canaries must match their detector's regex. Verifies the
    // canary spec stays in sync with the regex spec at runtime. ---

    #[test]
    fn registry_canaries_fire_their_detectors() {
        for def in REGISTRY {
            let Some(_spec) = def.canary else { continue };
            let canary = crate::canary::CanarySet::generate();
            let needle = canary
                .values()
                .into_iter()
                .find(|v| {
                    crate::registry::lookup(def.id)
                        .and_then(|d| d.canary.as_ref())
                        .map(|c| v.starts_with(c.prefix))
                        .unwrap_or(false)
                })
                .expect("canary value present for detector with canary spec");
            let ps = ps();
            let findings = ps.scan(&needle);
            assert!(
                findings.iter().any(|f| f.detector.as_str() == def.id),
                "[{}] generated canary {:?} did not fire its own detector",
                def.id,
                needle
            );
        }
    }

    // --- Hand-written tests that aren't covered by the registry driver. ---

    #[test]
    fn no_false_positive_on_normal_text() {
        let findings = ps().scan("Hello, this is a normal HTTP request body with some data.");
        assert!(
            findings.is_empty(),
            "normal English should fire nothing, got {:?}",
            findings,
        );
    }

    #[test]
    fn detects_token_embedded_in_json() {
        let token = format!("ghp_{}", "A".repeat(36));
        let json = format!(r#"{{"auth": "{token}"}}"#);
        let findings = ps().scan(&json);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector.as_str(), "github_pat");
    }

    #[test]
    fn detects_token_in_query_string() {
        let token = format!("npm_{}", "X".repeat(36));
        let url = format!("https://example.com/api?token={token}&foo=bar");
        let findings = ps().scan(&url);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector.as_str(), "npm_token");
    }

    #[test]
    fn detects_canary_token() {
        let canary = format!("ghp_{}", "C".repeat(36));
        let ps = PatternSet::with_canaries(vec![canary.clone()]).unwrap();
        let findings = ps.scan(&canary);
        assert!(
            findings
                .iter()
                .any(|f| f.detector.as_str() == "canary_token")
        );
    }

    #[test]
    fn display_detector_id() {
        // Display / Debug both emit the snake-case id — this is the
        // contract integration tests and SIEM dashboards rely on.
        let id = DetectorId::new("github_pat");
        assert_eq!(id.to_string(), "github_pat");
        assert_eq!(format!("{id:?}"), "github_pat");
    }
}
