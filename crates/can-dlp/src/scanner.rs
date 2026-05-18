use std::collections::HashMap;

use crate::decode::decode_layers;
use crate::decompress::decompress;
use crate::detectors::{DetectorAction, DetectorId, Finding, PatternSet};
use crate::entropy::{PerHostEntropyBudget, high_entropy_byte_count};
use crate::error::DlpError;
use crate::normalize::normalize;
use crate::scopes::DlpScopes;

/// Decide whether an HTTP header is worth feeding to the regex set.
///
/// We scan **by default** and only skip a small set of well-known
/// protocol/transport headers that never carry secrets. The earlier narrow
/// allow list (`authorization | cookie | proxy-authorization | x-*`) silently
/// missed common custom auth headers — `Api-Key`, `Apikey`, `Private-Token`
/// (GitLab), `Auth-Token`, `Refresh-Token`, etc. A skip list also degrades
/// gracefully: a new header name a future SDK invents is automatically in
/// scope.
fn header_is_scannable(lower_name: &str) -> bool {
    !matches!(
        lower_name,
        "host"
            | "user-agent"
            | "accept"
            | "accept-encoding"
            | "accept-language"
            | "accept-charset"
            | "accept-ranges"
            | "content-type"
            | "content-length"
            | "content-encoding"
            | "content-language"
            | "content-location"
            | "content-range"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "date"
            | "expect"
            | "te"
            | "trailer"
            | "range"
            | "vary"
            | "via"
            | "upgrade"
            | "expires"
            | "cache-control"
            | "pragma"
            | "if-match"
            | "if-none-match"
            | "if-modified-since"
            | "if-unmodified-since"
            | "if-range"
            | "max-forwards"
            | "origin"
            | "referer"
            | "server"
            | "etag"
            | "last-modified"
            | "location"
            | "allow"
            | "retry-after"
            | "warning"
            | "forwarded"
            | "from"
            | "dnt"
    )
}

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
    /// Borrow the underlying regex pattern set. Used by the streaming
    /// (R17) scan path to reuse the compiled regex set without holding
    /// a second copy.
    pub fn patterns(&self) -> &PatternSet {
        &self.patterns
    }

    /// Whether a given detector's verdict for `host` should escalate to
    /// a block under the scanner's current scope configuration. The
    /// streaming path uses this because it doesn't go through
    /// `evaluate_finding` (which assumes the whole-buffer flow). Keeps
    /// the scope-decision policy in one place.
    pub fn streaming_verdict(&self, detector: DetectorId, host: &str) -> DetectorAction {
        let allowed = self.scopes.is_allowed(detector, host);
        if allowed {
            DetectorAction::Warn
        } else {
            let default = detector.default_action();
            if self.strict && default == DetectorAction::Warn {
                DetectorAction::Block
            } else {
                default
            }
        }
    }

    pub fn new(
        canaries: Vec<String>,
        user_scopes: &HashMap<String, Vec<String>>,
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
            scopes: DlpScopes::new(user_scopes),
            max_decode_depth,
            do_decompress,
            strict,
        })
    }

    pub fn scan_headers(
        &self,
        headers: &[(String, String)],
        destination_host: &str,
    ) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();

        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            if header_is_scannable(&lower) {
                self.scan_text(value, destination_host, &mut verdicts);
            }
        }

        verdicts
    }

    pub fn scan_uri(&self, uri: &str, destination_host: &str) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();
        self.scan_text(uri, destination_host, &mut verdicts);
        verdicts
    }

    pub fn scan_body(
        &self,
        body: &[u8],
        content_encoding: Option<&str>,
        destination_host: &str,
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
                self.scan_text(text, destination_host, &mut verdicts);
            }
        }

        verdicts
    }

    pub fn check_entropy_budget(
        &self,
        body: &[u8],
        host: &str,
        budget: &PerHostEntropyBudget,
    ) -> Option<DlpError> {
        let high_bytes = high_entropy_byte_count(body, 32, 4.0);
        if high_bytes > 0 && !budget.record(host, high_bytes) {
            return Some(DlpError::EntropyBudgetExceeded {
                used: budget.used(host),
                budget: budget.budget(),
            });
        }
        None
    }

    fn scan_text(&self, text: &str, destination_host: &str, verdicts: &mut Vec<ScanVerdict>) {
        let mut seen_detectors: Vec<crate::detectors::DetectorId> = Vec::new();
        let mut scan_pass = |scanner: &Self, input: &str| {
            for finding in scanner.patterns.scan(input) {
                if seen_detectors.contains(&finding.detector) {
                    continue;
                }
                seen_detectors.push(finding.detector);
                let verdict = scanner.evaluate_finding(&finding, destination_host);
                verdicts.push(verdict);
            }
        };

        scan_pass(self, text);

        let normalized = normalize(text);
        if normalized != text {
            scan_pass(self, &normalized);
        }

        // R10: decode JSON `\uXXXX` and HTML entities. Re-scan both the raw
        // input and the normalised form because escape sequences can hide
        // behind unicode escapes (`ghp_…`) or HTML entities
        // (`&#103;hp_…`).
        let unescaped = crate::unescape::unescape(text);
        if unescaped != text {
            scan_pass(self, &unescaped);
            // Compose: normalise *then* unescape, in case the encoded form
            // itself contains zero-width chars or homoglyphs.
            let unescaped_norm = normalize(&unescaped);
            if unescaped_norm != unescaped {
                scan_pass(self, &unescaped_norm);
            }
        }
    }

    fn evaluate_finding(&self, finding: &Finding, destination_host: &str) -> ScanVerdict {
        let allowed = self.scopes.is_allowed(finding.detector, destination_host);

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
        let verdicts = s.scan_headers(&headers, "github.com");
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].detector, DetectorId::new("github_pat"));
        assert_eq!(verdicts[0].action, DetectorAction::Warn); // github.com is home domain
    }

    #[test]
    fn header_scan_blocks_github_pat_to_wrong_host() {
        let s = scanner();
        let token = format!("ghp_{}", "A".repeat(36));
        let headers = vec![("Authorization".to_string(), format!("token {token}"))];
        let verdicts = s.scan_headers(&headers, "evil.com");
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
        );
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].detector, DetectorId::new("npm_token"));
        assert_eq!(verdicts[0].action, DetectorAction::Warn); // home domain
    }

    #[test]
    fn body_scan_finds_encoded_token() {
        let s = scanner();
        let token = format!("ghp_{}", "B".repeat(36));
        let encoded = base64::engine::general_purpose::STANDARD.encode(&token);
        let verdicts = s.scan_body(encoded.as_bytes(), None, "evil.com");
        assert!(
            !verdicts.is_empty(),
            "should find base64-encoded token in body"
        );
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat"))
        );
    }

    #[test]
    fn body_scan_finds_gzip_token() {
        use std::io::Write;
        let s = scanner();
        let token = format!("ghp_{}", "C".repeat(36));
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(token.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        let verdicts = s.scan_body(&compressed, Some("gzip"), "evil.com");
        assert!(!verdicts.is_empty(), "should find token in gzip body");
    }

    #[test]
    fn ssh_key_always_blocked() {
        let s = scanner();
        let headers = vec![(
            "X-Custom".to_string(),
            "-----BEGIN RSA PRIVATE KEY-----".to_string(),
        )];
        let verdicts = s.scan_headers(&headers, "github.com");
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].detector, DetectorId::new("ssh_private_key"));
        assert_eq!(verdicts[0].action, DetectorAction::Block);
    }

    fn jwt_bearer() -> String {
        format!(
            "Bearer eyJ{}.eyJ{}.{}",
            "a".repeat(20),
            "b".repeat(20),
            "c".repeat(20),
        )
    }

    fn scanner_with_bearer_scope(domain: &str) -> DlpScanner {
        // R14: BearerToken scope is now configured under `[dlp.scopes]`,
        // not implicitly via `network.allow_domains`.
        let mut scopes = HashMap::new();
        scopes.insert("bearer_token".to_string(), vec![domain.to_string()]);
        DlpScanner::new(Vec::new(), &scopes, 32, true, false).unwrap()
    }

    #[test]
    fn bearer_token_allowed_to_allowed_domain() {
        let s = scanner_with_bearer_scope("api.example.com");
        let headers = vec![("Authorization".to_string(), jwt_bearer())];
        let verdicts = s.scan_headers(&headers, "api.example.com");
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].action, DetectorAction::Warn);
    }

    #[test]
    fn bearer_token_blocked_to_unknown_domain() {
        let s = scanner_with_bearer_scope("api.example.com");
        let headers = vec![("Authorization".to_string(), jwt_bearer())];
        let verdicts = s.scan_headers(&headers, "evil.com");
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].action, DetectorAction::Block);
    }

    #[test]
    fn canary_token_always_blocked() {
        let canary = format!("ghp_{}", "Z".repeat(36));
        let s = DlpScanner::new(vec![canary.clone()], &HashMap::new(), 32, true, false).unwrap();
        let headers = vec![("X-Token".to_string(), canary)];
        let verdicts = s.scan_headers(&headers, "github.com");
        assert!(verdicts.iter().any(|v| {
            v.detector == DetectorId::new("canary_token") && v.action == DetectorAction::Block
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
            detector: DetectorId::new("generic_high_entropy"),
            matched_text: "high_entropy_data".to_string(),
        };
        let verdict = s.evaluate_finding(&finding, "evil.com");
        assert_eq!(verdict.action, DetectorAction::Block);
    }

    #[test]
    fn entropy_budget_check() {
        let s = scanner();
        let budget = PerHostEntropyBudget::new(100);
        let high_entropy: Vec<u8> = (0..=255).cycle().take(256).collect();
        let result = s.check_entropy_budget(&high_entropy, "evil.example.com", &budget);
        // Might or might not exceed depending on window calculations,
        // but shouldn't panic
        let _ = result;
    }

    #[test]
    fn entropy_budget_is_isolated_per_host() {
        // R9: a request that pushes one host over its budget must not
        // block subsequent requests to another host.
        let s = scanner();
        let budget = PerHostEntropyBudget::new(50);
        let blob: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let _ = s.check_entropy_budget(&blob, "noisy.example.com", &budget);
        // Even after noisy.example.com is exhausted, a fresh budget exists
        // for a different destination.
        assert!(
            s.check_entropy_budget(b"hello", "clean.example.com", &budget)
                .is_none()
        );
    }

    #[test]
    fn non_sensitive_headers_skipped() {
        let s = scanner();
        let token = format!("ghp_{}", "A".repeat(36));
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), token),
        ];
        let verdicts = s.scan_headers(&headers, "evil.com");
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
        let verdicts = s.scan_headers(&headers, "evil.com");
        assert_eq!(verdicts.len(), 1);
    }

    #[test]
    fn custom_auth_headers_are_scanned() {
        // F4 regression: the previous allow list was `authorization | cookie |
        // proxy-authorization | x-*`. Custom auth headers that don't start
        // with `x-` were silently skipped. Pin each common offender so it
        // can't regress.
        let s = scanner();
        let token = format!("ghp_{}", "A".repeat(36));
        for header_name in [
            "Api-Key",
            "Apikey",
            "Api_Key",
            "Auth-Token",
            "Access-Token",
            "Refresh-Token",
            "Private-Token", // GitLab
            "Secret-Key",
            "Github-Token",
            "Cf-Access-Jwt-Assertion",
        ] {
            let headers = vec![(header_name.to_string(), token.clone())];
            let verdicts = s.scan_headers(&headers, "evil.com");
            assert_eq!(verdicts.len(), 1, "header {header_name} should be scanned");
        }
    }

    #[test]
    fn transport_headers_are_skipped() {
        let s = scanner();
        let token = format!("ghp_{}", "A".repeat(36));
        for header_name in [
            "Host",
            "User-Agent",
            "Accept",
            "Accept-Encoding",
            "Content-Type",
            "Content-Length",
            "Connection",
            "Date",
            "Cache-Control",
            "Referer",
        ] {
            let headers = vec![(header_name.to_string(), token.clone())];
            let verdicts = s.scan_headers(&headers, "evil.com");
            assert!(
                verdicts.is_empty(),
                "transport header {header_name} should be skipped"
            );
        }
    }

    #[test]
    fn detects_token_with_zero_width_chars() {
        let s = scanner();
        let token = format!("ghp_\u{200B}{}", "A".repeat(36));
        let headers = vec![("Authorization".to_string(), token)];
        let verdicts = s.scan_headers(&headers, "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat")),
            "should detect token hidden behind zero-width chars"
        );
    }

    #[test]
    fn detects_token_with_cyrillic_homoglyphs() {
        let s = scanner();
        // "gh" + Cyrillic р (U+0440) + "_" + 36 A's
        let token = format!("gh\u{0440}_{}", "A".repeat(36));
        let headers = vec![("X-Token".to_string(), token)];
        let verdicts = s.scan_headers(&headers, "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat")),
            "should detect token with Cyrillic homoglyph substitution"
        );
    }

    #[test]
    fn detects_token_with_combining_marks() {
        let s = scanner();
        // Zalgo-style: each char has a combining mark after it
        let token = format!("g\u{0300}h\u{0301}p\u{0302}_{}", "A".repeat(36));
        let headers = vec![("Authorization".to_string(), token)];
        let verdicts = s.scan_headers(&headers, "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat")),
            "should detect token hidden in Zalgo text"
        );
    }

    #[test]
    fn detects_token_with_fullwidth_chars() {
        let s = scanner();
        // "\u{FF47}\u{FF48}\u{FF50}\u{FF3F}" = fullwidth "ghp_"
        let token = format!("\u{FF47}\u{FF48}\u{FF50}\u{FF3F}{}", "A".repeat(36));
        let headers = vec![("X-Token".to_string(), token)];
        let verdicts = s.scan_headers(&headers, "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat")),
            "should detect token with fullwidth prefix"
        );
    }
}
