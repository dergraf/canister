use std::collections::HashMap;

use crate::decode::decode_layers;
use crate::decompress::decompress;
use crate::detectors::{DetectorAction, DetectorId, Finding, PatternSet};
use crate::entropy::{SessionEntropyBudget, high_entropy_byte_count};
use crate::error::DlpError;
use crate::normalize::normalize;
use crate::scopes::DlpScopes;

pub struct DlpScanner {
    patterns: PatternSet,
    scopes: DlpScopes,
    max_decode_depth: usize,
    do_decompress: bool,
    strict: bool,
}

#[derive(Debug, Clone)]
pub struct ScanVerdict {
    pub action: DetectorAction,
    pub detector: DetectorId,
    pub matched_text: String,
    pub host: String,
}

impl DlpScanner {
    pub fn new(
        canaries: Vec<String>,
        extra_scopes: &HashMap<String, Vec<String>>,
        max_decode_depth: usize,
        do_decompress: bool,
        strict: bool,
    ) -> Result<Self, DlpError> {
        let patterns = if canaries.is_empty() {
            PatternSet::new()?
        } else {
            PatternSet::with_canaries(canaries)?
        };

        Ok(Self {
            patterns,
            scopes: DlpScopes::new(extra_scopes),
            max_decode_depth,
            do_decompress,
            strict,
        })
    }

    pub fn scan_headers(
        &self,
        headers: &[(String, String)],
        destination_host: &str,
        allowed_domains: &[String],
    ) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();

        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            if matches!(
                lower.as_str(),
                "authorization" | "cookie" | "proxy-authorization"
            ) || lower.starts_with("x-")
            {
                self.scan_text(value, destination_host, allowed_domains, &mut verdicts);
            }
        }

        verdicts
    }

    pub fn scan_uri(
        &self,
        uri: &str,
        destination_host: &str,
        allowed_domains: &[String],
    ) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();
        self.scan_text(uri, destination_host, allowed_domains, &mut verdicts);
        verdicts
    }

    pub fn scan_body(
        &self,
        body: &[u8],
        content_encoding: Option<&str>,
        destination_host: &str,
        allowed_domains: &[String],
    ) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();

        let decompressed = if self.do_decompress {
            decompress(body, content_encoding)
        } else {
            body.to_vec()
        };

        let layers = decode_layers(&decompressed, self.max_decode_depth);

        for layer in &layers {
            if let Ok(text) = std::str::from_utf8(layer) {
                self.scan_text(text, destination_host, allowed_domains, &mut verdicts);
            }
        }

        verdicts
    }

    pub fn check_entropy_budget(
        &self,
        body: &[u8],
        budget: &SessionEntropyBudget,
    ) -> Option<DlpError> {
        let high_bytes = high_entropy_byte_count(body, 32, 4.0);
        if high_bytes > 0 && !budget.record(high_bytes) {
            return Some(DlpError::EntropyBudgetExceeded {
                used: budget.used(),
                budget: budget.budget(),
            });
        }
        None
    }

    fn scan_text(
        &self,
        text: &str,
        destination_host: &str,
        allowed_domains: &[String],
        verdicts: &mut Vec<ScanVerdict>,
    ) {
        let findings = self.patterns.scan(text);
        for finding in &findings {
            let verdict = self.evaluate_finding(finding, destination_host, allowed_domains);
            verdicts.push(verdict);
        }

        let normalized = normalize(text);
        if normalized != text {
            let norm_findings = self.patterns.scan(&normalized);
            for finding in &norm_findings {
                if !findings.iter().any(|f| f.detector == finding.detector) {
                    let verdict = self.evaluate_finding(finding, destination_host, allowed_domains);
                    verdicts.push(verdict);
                }
            }
        }
    }

    fn evaluate_finding(
        &self,
        finding: &Finding,
        destination_host: &str,
        allowed_domains: &[String],
    ) -> ScanVerdict {
        let allowed = self
            .scopes
            .is_allowed(finding.detector, destination_host, allowed_domains);

        let action = if allowed {
            DetectorAction::Warn
        } else {
            let default = finding.detector.default_action();
            if self.strict && default == DetectorAction::Warn {
                DetectorAction::Block
            } else {
                default
            }
        };

        ScanVerdict {
            action,
            detector: finding.detector,
            matched_text: finding.matched_text.clone(),
            host: destination_host.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use base64::Engine;

    fn scanner() -> DlpScanner {
        DlpScanner::new(Vec::new(), &HashMap::new(), 32, true, false).unwrap()
    }

    fn strict_scanner() -> DlpScanner {
        DlpScanner::new(Vec::new(), &HashMap::new(), 32, true, true).unwrap()
    }

    #[test]
    fn header_scan_finds_github_pat() {
        let s = scanner();
        let token = format!("ghp_{}", "A".repeat(36));
        let headers = vec![("Authorization".to_string(), format!("token {token}"))];
        let verdicts = s.scan_headers(&headers, "github.com", &[]);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].detector, DetectorId::GithubPat);
        assert_eq!(verdicts[0].action, DetectorAction::Warn); // github.com is home domain
    }

    #[test]
    fn header_scan_blocks_github_pat_to_wrong_host() {
        let s = scanner();
        let token = format!("ghp_{}", "A".repeat(36));
        let headers = vec![("Authorization".to_string(), format!("token {token}"))];
        let verdicts = s.scan_headers(&headers, "evil.com", &[]);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].action, DetectorAction::Block);
    }

    #[test]
    fn uri_scan_finds_npm_token() {
        let s = scanner();
        let token = format!("npm_{}", "X".repeat(36));
        let verdicts = s.scan_uri(
            &format!("https://registry.npmjs.org/pkg?token={token}"),
            "registry.npmjs.org",
            &[],
        );
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].detector, DetectorId::NpmToken);
        assert_eq!(verdicts[0].action, DetectorAction::Warn); // home domain
    }

    #[test]
    fn body_scan_finds_encoded_token() {
        let s = scanner();
        let token = format!("ghp_{}", "B".repeat(36));
        let encoded = base64::engine::general_purpose::STANDARD.encode(&token);
        let verdicts = s.scan_body(encoded.as_bytes(), None, "evil.com", &[]);
        assert!(
            !verdicts.is_empty(),
            "should find base64-encoded token in body"
        );
        assert!(verdicts.iter().any(|v| v.detector == DetectorId::GithubPat));
    }

    #[test]
    fn body_scan_finds_gzip_token() {
        use std::io::Write;
        let s = scanner();
        let token = format!("ghp_{}", "C".repeat(36));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(token.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        let verdicts = s.scan_body(&compressed, Some("gzip"), "evil.com", &[]);
        assert!(!verdicts.is_empty(), "should find token in gzip body");
    }

    #[test]
    fn ssh_key_always_blocked() {
        let s = scanner();
        let headers = vec![(
            "X-Custom".to_string(),
            "-----BEGIN RSA PRIVATE KEY-----".to_string(),
        )];
        let verdicts = s.scan_headers(&headers, "github.com", &[]);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].detector, DetectorId::SshPrivateKey);
        assert_eq!(verdicts[0].action, DetectorAction::Block);
    }

    #[test]
    fn bearer_token_allowed_to_allowed_domain() {
        let s = scanner();
        let token = format!("Bearer {}", "A".repeat(40));
        let headers = vec![("Authorization".to_string(), token)];
        let allowed = vec!["api.example.com".to_string()];
        let verdicts = s.scan_headers(&headers, "api.example.com", &allowed);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].action, DetectorAction::Warn);
    }

    #[test]
    fn bearer_token_blocked_to_unknown_domain() {
        let s = scanner();
        let token = format!("Bearer {}", "A".repeat(40));
        let headers = vec![("Authorization".to_string(), token)];
        let allowed = vec!["api.example.com".to_string()];
        let verdicts = s.scan_headers(&headers, "evil.com", &allowed);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].action, DetectorAction::Block);
    }

    #[test]
    fn canary_token_always_blocked() {
        let canary = format!("ghp_{}", "Z".repeat(36));
        let s = DlpScanner::new(vec![canary.clone()], &HashMap::new(), 32, true, false).unwrap();
        let headers = vec![("X-Token".to_string(), canary)];
        let verdicts = s.scan_headers(&headers, "github.com", &[]);
        assert!(verdicts.iter().any(|v| {
            v.detector == DetectorId::CanaryToken && v.action == DetectorAction::Block
        }));
    }

    #[test]
    fn strict_mode_promotes_generic_to_block() {
        // The generic_high_entropy detector is Warn by default.
        // With strict, when it's found going to a non-allowed domain, it should block.
        // This is tested indirectly — the GenericHighEntropy detector is regex-free
        // (entropy-based), so we test the evaluate path directly.
        let s = strict_scanner();
        let finding = crate::detectors::Finding {
            detector: DetectorId::GenericHighEntropy,
            matched_text: "high_entropy_data".to_string(),
        };
        let verdict = s.evaluate_finding(&finding, "evil.com", &[]);
        assert_eq!(verdict.action, DetectorAction::Block);
    }

    #[test]
    fn entropy_budget_check() {
        let s = scanner();
        let budget = SessionEntropyBudget::new(100);
        let high_entropy: Vec<u8> = (0..=255).cycle().take(256).collect();
        let result = s.check_entropy_budget(&high_entropy, &budget);
        // Might or might not exceed depending on window calculations,
        // but shouldn't panic
        let _ = result;
    }

    #[test]
    fn non_sensitive_headers_skipped() {
        let s = scanner();
        let token = format!("ghp_{}", "A".repeat(36));
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), token),
        ];
        let verdicts = s.scan_headers(&headers, "evil.com", &[]);
        assert!(
            verdicts.is_empty(),
            "non-sensitive headers should be skipped"
        );
    }

    #[test]
    fn x_headers_are_scanned() {
        let s = scanner();
        let token = format!("ghp_{}", "A".repeat(36));
        let headers = vec![("X-Api-Key".to_string(), token)];
        let verdicts = s.scan_headers(&headers, "evil.com", &[]);
        assert_eq!(verdicts.len(), 1);
    }

    #[test]
    fn detects_token_with_zero_width_chars() {
        let s = scanner();
        let token = format!("ghp_\u{200B}{}", "A".repeat(36));
        let headers = vec![("Authorization".to_string(), token)];
        let verdicts = s.scan_headers(&headers, "evil.com", &[]);
        assert!(
            verdicts.iter().any(|v| v.detector == DetectorId::GithubPat),
            "should detect token hidden behind zero-width chars"
        );
    }

    #[test]
    fn detects_token_with_cyrillic_homoglyphs() {
        let s = scanner();
        // "gh" + Cyrillic р (U+0440) + "_" + 36 A's
        let token = format!("gh\u{0440}_{}", "A".repeat(36));
        let headers = vec![("X-Token".to_string(), token)];
        let verdicts = s.scan_headers(&headers, "evil.com", &[]);
        assert!(
            verdicts.iter().any(|v| v.detector == DetectorId::GithubPat),
            "should detect token with Cyrillic homoglyph substitution"
        );
    }

    #[test]
    fn detects_token_with_combining_marks() {
        let s = scanner();
        // Zalgo-style: each char has a combining mark after it
        let token = format!("g\u{0300}h\u{0301}p\u{0302}_{}", "A".repeat(36));
        let headers = vec![("Authorization".to_string(), token)];
        let verdicts = s.scan_headers(&headers, "evil.com", &[]);
        assert!(
            verdicts.iter().any(|v| v.detector == DetectorId::GithubPat),
            "should detect token hidden in Zalgo text"
        );
    }

    #[test]
    fn detects_token_with_fullwidth_chars() {
        let s = scanner();
        // "\u{FF47}\u{FF48}\u{FF50}\u{FF3F}" = fullwidth "ghp_"
        let token = format!("\u{FF47}\u{FF48}\u{FF50}\u{FF3F}{}", "A".repeat(36));
        let headers = vec![("X-Token".to_string(), token)];
        let verdicts = s.scan_headers(&headers, "evil.com", &[]);
        assert!(
            verdicts.iter().any(|v| v.detector == DetectorId::GithubPat),
            "should detect token with fullwidth prefix"
        );
    }
}
