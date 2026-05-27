use std::collections::HashMap;

use crate::decode::decode_layers;
use crate::decompress::decompress;
use crate::detectors::{DetectorAction, DetectorId, Finding, PatternSet};
use crate::entropy::{PerHostEntropyBudget, high_entropy_byte_count};
use crate::error::DlpError;
use crate::extract::{Extracted, Extractor, StringSource};
use crate::scopes::DlpScopes;
use crate::transforms::{DEFAULT_COST_BUDGET, TransformKind, transforms_of};

pub struct DlpScanner {
    patterns: PatternSet,
    scopes: DlpScopes,
    extractor: Extractor,
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
    /// Where in the request the matched bytes originated. `None`
    /// preserves the pre-PR2 opaque-bytes shape for callers that
    /// haven't migrated to `scan_request`.
    pub source: Option<StringSource>,
}

impl DlpScanner {
    /// Borrow the underlying regex pattern set. Used by the streaming
    /// (R17) scan path to reuse the compiled regex set without holding
    /// a second copy.
    pub fn patterns(&self) -> &PatternSet {
        &self.patterns
    }

    /// Whether `detector_id`'s credential is authorized to flow to
    /// `host` under the current scope table (home domains +
    /// `[[host]] allow_credentials`). The fake-secret swap uses this as
    /// its single authorization gate: it swaps a fake for the real value
    /// only where this returns `true`, independent of enforcement mode —
    /// so monitor mode never leaks a real secret to an unauthorized host.
    /// Unknown ids return `false` (fail closed).
    pub fn credential_allowed(&self, detector_id: &str, host: &str) -> bool {
        match crate::registry::lookup(detector_id) {
            Some(def) => self.scopes.is_allowed(DetectorId::new(def.id), host),
            None => false,
        }
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
        Self::with_extractor(
            canaries,
            user_scopes,
            max_decode_depth,
            do_decompress,
            strict,
            Extractor::default(),
        )
    }

    /// Same as [`Self::new`] but with a caller-configured extractor —
    /// lets the proxy thread through `max_json_parse_bytes` from the
    /// policy.
    pub fn with_extractor(
        canaries: Vec<String>,
        user_scopes: &HashMap<String, Vec<String>>,
        max_decode_depth: usize,
        do_decompress: bool,
        strict: bool,
        extractor: Extractor,
    ) -> Result<Self, DlpError> {
        let patterns = if canaries.is_empty() {
            PatternSet::new()?
        } else {
            PatternSet::with_canaries(canaries)?
        };

        Ok(Self {
            patterns,
            scopes: DlpScopes::new(user_scopes),
            extractor,
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
        let extracted = self.extractor.extract_headers(headers);
        self.scan_extracted(&extracted, destination_host, &mut verdicts);
        verdicts
    }

    /// Scan a separately-collected set of HTTP/1.1 chunked trailers.
    /// Exists as a standalone entry point because the proxy already
    /// scans request headers and URI eagerly before buffering the
    /// body; trailers only become available after the buffer
    /// completes, so they're scanned in their own pass.
    pub fn scan_trailers(
        &self,
        trailers: &[(String, String)],
        destination_host: &str,
    ) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();
        let extracted = self.extractor.extract_trailers(trailers);
        self.scan_extracted(&extracted, destination_host, &mut verdicts);
        verdicts
    }

    pub fn scan_uri(&self, uri: &str, destination_host: &str) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();
        let extracted = self.extractor.extract_uri(uri);
        self.scan_extracted(&extracted, destination_host, &mut verdicts);
        verdicts
    }

    pub fn scan_body(
        &self,
        body: &[u8],
        content_encoding: Option<&str>,
        destination_host: &str,
    ) -> Vec<ScanVerdict> {
        self.scan_body_with_type(body, content_encoding, None, destination_host)
    }

    /// Like [`Self::scan_body`] but takes `Content-Type` too, enabling
    /// the structured JSON walker. Returns verdicts whose `source`
    /// points to the JSON path (`json:user.tokens[0]`) when the leak
    /// lands on a parsed string value.
    pub fn scan_body_with_type(
        &self,
        body: &[u8],
        content_encoding: Option<&str>,
        content_type: Option<&str>,
        destination_host: &str,
    ) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();

        let decompressed = if self.do_decompress {
            decompress(body, content_encoding)
        } else {
            body.to_vec()
        };

        let extracted = self.extractor.extract_body(&decompressed, content_type);
        self.scan_extracted(&extracted, destination_host, &mut verdicts);
        verdicts
    }

    /// Single-call entry point that scans the entire request shape —
    /// headers, URI, body — and returns verdicts tagged with the
    /// originating [`StringSource`]. Preferred for new call sites; the
    /// per-shape `scan_*` wrappers remain for backward compatibility
    /// within the workspace.
    pub fn scan_request(
        &self,
        headers: &[(String, String)],
        uri: &str,
        body: &[u8],
        content_type: Option<&str>,
        content_encoding: Option<&str>,
        destination_host: &str,
    ) -> Vec<ScanVerdict> {
        self.scan_request_with_trailers(
            headers,
            uri,
            body,
            content_type,
            content_encoding,
            &[],
            destination_host,
        )
    }

    /// Variant of [`Self::scan_request`] that also scans HTTP/1.1
    /// chunked **trailers**. The proxy uses this on bodies it has
    /// fully collected, since trailers arrive after the body. Empty
    /// `trailers` is the no-op equivalent of [`Self::scan_request`].
    #[allow(clippy::too_many_arguments)] // every arg is a distinct request shape; bundling into a struct would just shift the noise
    pub fn scan_request_with_trailers(
        &self,
        headers: &[(String, String)],
        uri: &str,
        body: &[u8],
        content_type: Option<&str>,
        content_encoding: Option<&str>,
        trailers: &[(String, String)],
        destination_host: &str,
    ) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();

        let header_extracted = self.extractor.extract_headers(headers);
        self.scan_extracted(&header_extracted, destination_host, &mut verdicts);

        let uri_extracted = self.extractor.extract_uri(uri);
        self.scan_extracted(&uri_extracted, destination_host, &mut verdicts);

        let decompressed: Vec<u8> = if self.do_decompress {
            decompress(body, content_encoding)
        } else {
            body.to_vec()
        };
        let body_extracted = self.extractor.extract_body(&decompressed, content_type);
        self.scan_extracted(&body_extracted, destination_host, &mut verdicts);

        let trailer_extracted = self.extractor.extract_trailers(trailers);
        self.scan_extracted(&trailer_extracted, destination_host, &mut verdicts);

        verdicts
    }

    /// Symmetric to [`Self::scan_request`] but for the upstream's
    /// response. Walks every response header (no skip-list) **and**
    /// the body through the same extractor + decode + normalize +
    /// regex pipeline, so a canary echoed back as
    /// `Set-Cookie: AKIA…`, redirected via `Location:`,
    /// embedded at `body.data.echo` of a JSON response, or wrapped in
    /// `base64(strip_separators(canary))` is caught with the same
    /// rigor as a request-direction leak.
    ///
    /// Returns verdicts the caller can either block on (the typical
    /// case) or downgrade to warnings under monitor mode. Per-detector
    /// scope policy still applies — a `github_pat` echoed by
    /// `*.github.com` is a `Warn`, not a `Block`.
    pub fn scan_response(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        content_type: Option<&str>,
        content_encoding: Option<&str>,
        upstream_host: &str,
    ) -> Vec<ScanVerdict> {
        self.scan_response_with_trailers(
            headers,
            body,
            content_type,
            content_encoding,
            &[],
            upstream_host,
        )
    }

    /// Variant of [`Self::scan_response`] that also scans response
    /// trailers. An upstream serving chunked transfer-encoding with
    /// a `Trailer:` declaration can hand back the canary in a
    /// trailer just as readily as in `Set-Cookie`, and without this
    /// arm it would bypass DLP.
    pub fn scan_response_with_trailers(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        content_type: Option<&str>,
        content_encoding: Option<&str>,
        trailers: &[(String, String)],
        upstream_host: &str,
    ) -> Vec<ScanVerdict> {
        let mut verdicts = Vec::new();

        let header_extracted = self.extractor.extract_headers(headers);
        self.scan_extracted(&header_extracted, upstream_host, &mut verdicts);

        let decompressed: Vec<u8> = if self.do_decompress {
            decompress(body, content_encoding)
        } else {
            body.to_vec()
        };
        let body_extracted = self.extractor.extract_body(&decompressed, content_type);
        self.scan_extracted(&body_extracted, upstream_host, &mut verdicts);

        let trailer_extracted = self.extractor.extract_trailers(trailers);
        self.scan_extracted(&trailer_extracted, upstream_host, &mut verdicts);

        verdicts
    }

    /// Run the decode chain over each [`Extracted`] unit and attach
    /// its source to every emitted verdict. Centralised so all the
    /// `scan_*` methods share one path.
    fn scan_extracted(
        &self,
        units: &[Extracted<'_>],
        destination_host: &str,
        verdicts: &mut Vec<ScanVerdict>,
    ) {
        for unit in units {
            self.scan_bytes_with_layers(
                &unit.bytes,
                destination_host,
                Some(&unit.source),
                verdicts,
            );
        }
    }

    /// Run the decode chain over `bytes`, then `scan_text` each UTF-8
    /// layer. Source is propagated to every emitted verdict.
    fn scan_bytes_with_layers(
        &self,
        bytes: &[u8],
        destination_host: &str,
        source: Option<&StringSource>,
        verdicts: &mut Vec<ScanVerdict>,
    ) {
        let layers = decode_layers(bytes, self.max_decode_depth, DEFAULT_COST_BUDGET);
        for layer in &layers {
            if let Ok(text) = std::str::from_utf8(layer) {
                self.scan_text(text, destination_host, source, verdicts);
            }
        }
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

    fn scan_text(
        &self,
        text: &str,
        destination_host: &str,
        source: Option<&StringSource>,
        verdicts: &mut Vec<ScanVerdict>,
    ) {
        let mut seen_detectors: Vec<crate::detectors::DetectorId> = Vec::new();
        let mut scan_pass = |scanner: &Self, input: &str| {
            for finding in scanner.patterns.scan(input) {
                if seen_detectors.contains(&finding.detector) {
                    continue;
                }
                seen_detectors.push(finding.detector);
                let verdict = scanner.evaluate_finding(&finding, destination_host, source);
                verdicts.push(verdict);
            }
        };

        // 1) Raw layer.
        scan_pass(self, text);

        // 2) Normalize pass — apply each `Normalize` transform from the
        //    registry, and scan the cross-product of N=1 compositions
        //    (e.g. normalize ∘ unescape) so escape sequences hiding
        //    behind homoglyphs are caught.
        let mut produced: Vec<String> = vec![text.to_string()];
        for tf in transforms_of(TransformKind::Normalize) {
            let mut new = Vec::new();
            for src in &produced {
                for out in (tf.apply)(src.as_bytes()) {
                    if let Ok(s) = String::from_utf8(out) {
                        if !produced.iter().any(|p| p == &s) && !new.iter().any(|n| n == &s) {
                            scan_pass(self, &s);
                            new.push(s);
                        }
                    }
                }
            }
            produced.extend(new);
        }

        // 3) Last-resort transforms (reverse, rot13) — applied once to
        //    the original layer only, no composition. Detector regexes
        //    anchor on specific prefixes so the FP risk stays bounded;
        //    composing these would amplify it.
        for tf in transforms_of(TransformKind::LastResort) {
            for out in (tf.apply)(text.as_bytes()) {
                if let Ok(s) = String::from_utf8(out) {
                    if s != text {
                        scan_pass(self, &s);
                    }
                }
            }
        }
    }

    fn evaluate_finding(
        &self,
        finding: &Finding,
        destination_host: &str,
        source: Option<&StringSource>,
    ) -> ScanVerdict {
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
            source: source.cloned(),
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
        // Post-PR2 the extractor yields multiple verdicts for the
        // same detector — one per source the token appears in
        // (UriQueryValue { key: "token" } plus the BodyRaw fallback).
        // That's intentional: each source gets its own attributable
        // verdict.
        assert!(!verdicts.is_empty());
        assert!(
            verdicts
                .iter()
                .all(|v| v.detector == DetectorId::new("npm_token"))
        );
        assert!(verdicts.iter().all(|v| v.action == DetectorAction::Warn)); // home domain
        // And at least one verdict points at the query-value source.
        assert!(verdicts.iter().any(|v| matches!(
            v.source.as_ref(),
            Some(StringSource::UriQueryValue { key }) if key == "token"
        )));
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
        // BearerToken scope requires an explicit per-host opt-in. In
        // production this comes from a `[[host]] allow_credentials =
        // ["bearer_token"]` block; here we synthesise the same
        // detector→hosts map the proxy passes in.
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
        let verdict = s.evaluate_finding(&finding, "evil.com", None);
        assert_eq!(verdict.action, DetectorAction::Block);
    }

    #[test]
    fn scan_request_attributes_json_string_path() {
        // Drives the PR2 contract: a canary leaked inside a JSON
        // body must produce a verdict whose `source` names the exact
        // field path. This is what makes "AKIA in body to evil.com"
        // become "AKIA in body.user.tokens[0] to evil.com" in logs.
        let s = scanner();
        let body = br#"{"user":{"tokens":["AKIA0123456789ABCDEF","other"]},"meta":{}}"#;
        let verdicts = s.scan_request(
            &[],
            "/api/post",
            body,
            Some("application/json"),
            None,
            "evil.com",
        );
        let aws = DetectorId::new("aws_access_key");
        assert!(verdicts.iter().any(|v| v.detector == aws));
        let attributed = verdicts.iter().any(|v| {
            v.detector == aws
                && matches!(
                    v.source.as_ref(),
                    Some(StringSource::JsonString { path }) if path == "user.tokens[0]"
                )
        });
        assert!(
            attributed,
            "expected a verdict with source = json:user.tokens[0]"
        );
    }

    #[test]
    fn scan_request_attributes_header_source() {
        let s = scanner();
        let key = "AKIA0123456789ABCDEF";
        let verdicts = s.scan_request(
            &[("X-Api-Key".to_string(), key.to_string())],
            "/",
            b"",
            None,
            None,
            "evil.com",
        );
        let aws = DetectorId::new("aws_access_key");
        assert!(verdicts.iter().any(|v| {
            v.detector == aws
                && matches!(
                    v.source.as_ref(),
                    Some(StringSource::HeaderValue { name }) if name == "X-Api-Key"
                )
        }));
    }

    #[test]
    fn scan_request_attributes_uri_query_source() {
        let s = scanner();
        let key = "AKIA0123456789ABCDEF";
        let verdicts = s.scan_request(
            &[],
            &format!("https://evil.com/leak?token={key}"),
            b"",
            None,
            None,
            "evil.com",
        );
        let aws = DetectorId::new("aws_access_key");
        assert!(verdicts.iter().any(|v| {
            v.detector == aws
                && matches!(
                    v.source.as_ref(),
                    Some(StringSource::UriQueryValue { key }) if key == "token"
                )
        }));
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
    fn formerly_skipped_headers_are_now_scanned() {
        // Inverse of the old "non_sensitive_headers_skipped" test.
        // The skip-list was an exfil vector: an attacker controls
        // header values end-to-end, so a worker could leak `ghp_…`
        // through `Accept:` and bypass DLP. Removing the skip-list
        // closes that gap; the cost is one regex run per header,
        // which is negligible.
        let s = scanner();
        let token = format!("ghp_{}", "A".repeat(36));
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), token),
        ];
        let verdicts = s.scan_headers(&headers, "evil.com");
        assert!(
            verdicts.iter().any(|v| v.detector.as_str() == "github_pat"),
            "header value carrying a credential must fire even on \
             a header that used to be skip-listed"
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
    fn transport_headers_are_now_scanned_too() {
        // The "transport headers are skipped" rule was a security
        // bug. Pin the new contract: a credential stuffed into any
        // header — including transport / protocol ones — fires. The
        // detector regex anchors on the credential prefix, so a
        // legitimate `Date:` or `Cache-Control:` value never matches.
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
            "Origin",
            "Cookie",
            "Forwarded",
        ] {
            let headers = vec![(header_name.to_string(), token.clone())];
            let verdicts = s.scan_headers(&headers, "evil.com");
            assert!(
                verdicts.iter().any(|v| v.detector.as_str() == "github_pat"),
                "header {header_name} carrying a credential must fire"
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

    fn encode_for(kind: &str, text: &str) -> String {
        use base64::engine::general_purpose::{STANDARD, URL_SAFE};
        match kind {
            "base64" => STANDARD.encode(text),
            "base64url" => URL_SAFE.encode(text),
            "hex" => text.bytes().map(|b| format!("{b:02x}")).collect(),
            "double_base64" => STANDARD.encode(STANDARD.encode(text)),
            other => panic!("unknown encoding {other}"),
        }
    }

    fn wrap_for(channel: &str, encoded: &str) -> String {
        match channel {
            "Cookie" => format!("session={encoded}"),
            _ => encoded.to_string(),
        }
    }

    /// F-encoded-headers regression matrix. Mirrors the operator-side
    /// fuzzer (header channels × encodings) that exposed the gap: the
    /// regex set runs against the layer-decoded forms of every
    /// scannable header value, not just the raw bytes.
    #[test]
    fn encoded_aws_keys_in_headers_are_detected() {
        let s = scanner();
        let raw_key = "AKIAIOSFODNN7EXAMPLE";

        for channel in ["Authorization", "X-Api-Key", "Cookie"] {
            for enc in ["base64", "base64url", "hex", "double_base64"] {
                let encoded = encode_for(enc, raw_key);
                let value = wrap_for(channel, &encoded);
                let headers = vec![(channel.to_string(), value.clone())];
                let verdicts = s.scan_headers(&headers, "evil.com");
                assert!(
                    verdicts
                        .iter()
                        .any(|v| v.detector == DetectorId::new("aws_access_key")),
                    "channel={channel} enc={enc} value={value} should fire aws_access_key"
                );
            }
        }
    }

    /// Creative-attack coverage matrix. Every encoding the dlp-test.py
    /// `--creative` mode probes is mirrored here so we can see at-a-
    /// glance which ones the scanner currently catches, and so
    /// regressions are pinned individually.
    ///
    /// Encodings marked `should_catch=true` are the realistic exfil
    /// vectors we want to fail-loud on. Encodings marked
    /// `should_catch=false` are documented gaps — pure-bruteforce
    /// transformations (rot13, single-byte XOR, full reverse) we
    /// intentionally don't try, because auto-decoding them produces
    /// too many false positives. They live here so a future
    /// improvement can flip the flag and watch the assertion fail
    /// until the decoder is implemented.
    #[test]
    fn creative_attack_matrix_coverage() {
        use base64::engine::general_purpose::STANDARD;
        use std::io::Write;

        let s = scanner();
        let raw = "AKIA0123456789ABCDEF";

        fn rfc4648_base32(input: &[u8]) -> String {
            const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let mut out = String::new();
            let mut bit_buf: u32 = 0;
            let mut bit_count: u32 = 0;
            for &byte in input {
                bit_buf = (bit_buf << 8) | byte as u32;
                bit_count += 8;
                while bit_count >= 5 {
                    bit_count -= 5;
                    let idx = (bit_buf >> bit_count) & 0b11111;
                    out.push(ALPHABET[idx as usize] as char);
                }
            }
            if bit_count > 0 {
                let idx = (bit_buf << (5 - bit_count)) & 0b11111;
                out.push(ALPHABET[idx as usize] as char);
            }
            while out.len() % 8 != 0 {
                out.push('=');
            }
            out
        }

        fn rot13(s: &str) -> String {
            s.chars()
                .map(|c| match c {
                    'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
                    'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
                    _ => c,
                })
                .collect()
        }

        fn xor_hex(s: &str, key: u8) -> String {
            s.bytes().map(|b| format!("{:02x}", b ^ key)).collect()
        }

        fn gzip_b64(s: &str) -> String {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(s.as_bytes()).unwrap();
            STANDARD.encode(e.finish().unwrap())
        }

        fn deflate_b64(s: &str) -> String {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(s.as_bytes()).unwrap();
            STANDARD.encode(e.finish().unwrap())
        }

        // Mirror the fuzzer's `Bearer <payload>` framing — the
        // header-channel bugs all surfaced through this exact shape,
        // so the matrix tests the same prefix.
        fn ascii85_enc(input: &[u8]) -> String {
            let mut out = String::new();
            let mut i = 0;
            while i + 4 <= input.len() {
                let word = u32::from_be_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]]);
                let mut buf = [0u8; 5];
                let mut n = word as u64;
                for slot in buf.iter_mut().rev() {
                    *slot = (n % 85) as u8 + b'!';
                    n /= 85;
                }
                out.push_str(std::str::from_utf8(&buf).unwrap());
                i += 4;
            }
            if i < input.len() {
                let mut padded = [0u8; 4];
                let extra = input.len() - i;
                padded[..extra].copy_from_slice(&input[i..]);
                let word = u32::from_be_bytes(padded);
                let mut buf = [0u8; 5];
                let mut n = word as u64;
                for slot in buf.iter_mut().rev() {
                    *slot = (n % 85) as u8 + b'!';
                    n /= 85;
                }
                out.push_str(std::str::from_utf8(&buf[..extra + 1]).unwrap());
            }
            out
        }
        fn base85_rfc1924_enc(input: &[u8]) -> String {
            const ALPHABET: &[u8] =
                b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
            let mut out = String::new();
            let mut i = 0;
            while i < input.len() {
                let chunk_len = (input.len() - i).min(4);
                let mut buf4 = [0u8; 4];
                buf4[..chunk_len].copy_from_slice(&input[i..i + chunk_len]);
                let word = u32::from_be_bytes(buf4);
                let mut buf5 = [0u8; 5];
                let mut n = word as u64;
                for slot in buf5.iter_mut().rev() {
                    *slot = ALPHABET[(n % 85) as usize];
                    n /= 85;
                }
                out.push_str(std::str::from_utf8(&buf5[..chunk_len + 1]).unwrap());
                i += chunk_len;
            }
            out
        }
        fn utf16_hex(s: &str) -> String {
            s.encode_utf16()
                .flat_map(|u| u.to_le_bytes())
                .map(|b| format!("{b:02x}"))
                .collect()
        }

        let cases: &[(&str, String, bool)] = &[
            // Realistic attacks we want to catch.
            (
                "base32",
                format!("Bearer {}", rfc4648_base32(raw.as_bytes())),
                true,
            ),
            (
                "ascii85",
                format!("Bearer {}", ascii85_enc(raw.as_bytes())),
                true,
            ),
            // Cookie-style framing (the fuzzer's `session=<payload>`)
            // is harder than `Bearer <payload>` because no whitespace
            // breaks the b85-charset run, so the prefix shifts the
            // 5-char chunk alignment. The sliding decoder covers it.
            (
                "ascii85_cookie",
                format!("session={}", ascii85_enc(raw.as_bytes())),
                true,
            ),
            (
                "base85",
                format!("Bearer {}", base85_rfc1924_enc(raw.as_bytes())),
                true,
            ),
            (
                "base85_cookie",
                format!("session={}", base85_rfc1924_enc(raw.as_bytes())),
                true,
            ),
            ("gzip_base64", format!("Bearer {}", gzip_b64(raw)), true),
            (
                "deflate_base64",
                format!("Bearer {}", deflate_b64(raw)),
                true,
            ),
            ("utf16_hex", utf16_hex(raw), true),
            (
                "py_byte_escape",
                raw.bytes().map(|b| format!("\\x{b:02X}")).collect(),
                true,
            ),
            (
                "html_entities",
                raw.bytes().map(|b| format!("&#x{b:02X};")).collect(),
                true,
            ),
            (
                "json_unicode",
                raw.bytes().map(|b| format!("\\u{b:04X}")).collect(),
                true,
            ),
            (
                "interleaved_zwsp",
                raw.chars().map(|c| format!("{c}\u{200B}")).collect(),
                true,
            ),
            (
                "fullwidth",
                raw.chars()
                    .map(|c| {
                        let cp = c as u32;
                        if (0x21..=0x7E).contains(&cp) {
                            char::from_u32(cp - 0x20 + 0xFF00).unwrap()
                        } else {
                            c
                        }
                    })
                    .collect(),
                true,
            ),
            // Cheap secondary transforms now handled by `scan_text`.
            ("reverse", raw.chars().rev().collect(), true),
            ("rot13", rot13(raw), true),
            (
                "interleaved_dash",
                raw.chars()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join("-"),
                true,
            ),
            (
                "interleaved_space",
                raw.chars()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(" "),
                true,
            ),
            // Single-byte XOR + hex transport. Caught now by the
            // targeted XOR brute-force: the decoder searches for each
            // registered canary prefix (`AKIA`, `ghp_`, `npm_`) XOR'd
            // with every byte key, and on a hit decodes the whole
            // buffer with the discovered key.
            ("xor_a5_hex", xor_hex(raw, 0xA5), true),
        ];

        let mut report = String::from("\n=== creative-attack coverage ===\n");
        let mut unexpected_misses = Vec::new();
        let mut unexpected_hits = Vec::new();

        for (name, value, should_catch) in cases {
            let verdicts = s.scan_headers(&[("X-Custom".to_string(), value.clone())], "evil.com");
            let hit = verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("aws_access_key"));
            let marker = if hit == *should_catch {
                "OK   "
            } else if *should_catch {
                unexpected_misses.push(*name);
                "MISS "
            } else {
                unexpected_hits.push(*name);
                "HIT  "
            };
            let preview: String = value.chars().take(60).collect();
            report.push_str(&format!(
                "{marker} {name:20} expect={} preview={preview:?}\n",
                if *should_catch { "catch" } else { "skip " },
            ));
        }

        eprintln!("{report}");
        assert!(
            unexpected_misses.is_empty(),
            "encodings we expected to catch but didn't: {unexpected_misses:?}"
        );
        assert!(
            unexpected_hits.is_empty(),
            "encodings we expected to skip but caught (false positive?): {unexpected_hits:?}"
        );
    }

    #[test]
    fn encoded_aws_key_in_uri_query_is_detected() {
        use base64::engine::general_purpose::STANDARD;

        let s = scanner();
        let raw_key = "AKIAIOSFODNN7EXAMPLE";
        let encoded = STANDARD.encode(raw_key);
        let uri = format!("https://evil.com/exfil?payload={encoded}");

        let verdicts = s.scan_uri(&uri, "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("aws_access_key")),
            "encoded key in query string should fire aws_access_key"
        );
    }

    /// Channel-coverage regression: each of these (encoding × channel)
    /// combinations matched a bug reported by the dlp-test.py fuzzer.
    /// Catches them at the layer they failed at — `scan_uri` for path
    /// and query exfil, `scan_body` for JSON-body exfil — so a
    /// regression in fragment decoding or strip-separator passes fails
    /// loud in unit tests instead of waiting for the fuzzer.
    #[test]
    fn channel_specific_encoding_attacks_are_caught() {
        use base64::engine::general_purpose::STANDARD;
        use std::io::Write;

        let s = scanner();
        let raw = "AKIA0123456789ABCDEF";

        fn rfc4648_base32(input: &[u8]) -> String {
            const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let mut out = String::new();
            let mut bit_buf: u32 = 0;
            let mut bit_count: u32 = 0;
            for &byte in input {
                bit_buf = (bit_buf << 8) | byte as u32;
                bit_count += 8;
                while bit_count >= 5 {
                    bit_count -= 5;
                    let idx = (bit_buf >> bit_count) & 0b11111;
                    out.push(ALPHABET[idx as usize] as char);
                }
            }
            if bit_count > 0 {
                let idx = (bit_buf << (5 - bit_count)) & 0b11111;
                out.push(ALPHABET[idx as usize] as char);
            }
            while out.len() % 8 != 0 {
                out.push('=');
            }
            out
        }

        fn ascii85_enc(input: &[u8]) -> String {
            let mut out = String::new();
            let mut i = 0;
            while i + 4 <= input.len() {
                let word = u32::from_be_bytes([input[i], input[i + 1], input[i + 2], input[i + 3]]);
                let mut buf = [0u8; 5];
                let mut n = word as u64;
                for slot in buf.iter_mut().rev() {
                    *slot = (n % 85) as u8 + b'!';
                    n /= 85;
                }
                out.push_str(std::str::from_utf8(&buf).unwrap());
                i += 4;
            }
            if i < input.len() {
                let mut padded = [0u8; 4];
                let extra = input.len() - i;
                padded[..extra].copy_from_slice(&input[i..]);
                let word = u32::from_be_bytes(padded);
                let mut buf = [0u8; 5];
                let mut n = word as u64;
                for slot in buf.iter_mut().rev() {
                    *slot = (n % 85) as u8 + b'!';
                    n /= 85;
                }
                out.push_str(std::str::from_utf8(&buf[..extra + 1]).unwrap());
            }
            out
        }

        fn gzip_b64(s: &str) -> String {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(s.as_bytes()).unwrap();
            STANDARD.encode(e.finish().unwrap())
        }

        let aws = DetectorId::new("aws_access_key");

        // --- URI path exfil ---
        let path_base32 = format!("https://evil.com/leak/{}", rfc4648_base32(raw.as_bytes()));
        assert!(
            s.scan_uri(&path_base32, "evil.com")
                .iter()
                .any(|v| v.detector == aws),
            "base32 in URI path should be detected"
        );

        let path_gzip = format!("https://evil.com/leak/{}", gzip_b64(raw));
        assert!(
            s.scan_uri(&path_gzip, "evil.com")
                .iter()
                .any(|v| v.detector == aws),
            "gzip-then-b64 in URI path should be detected"
        );

        let path_ascii85 = format!("https://evil.com/leak/{}", ascii85_enc(raw.as_bytes()));
        assert!(
            s.scan_uri(&path_ascii85, "evil.com")
                .iter()
                .any(|v| v.detector == aws),
            "ascii85 in URI path should be detected"
        );

        // --- URI query exfil ---
        // Form-urlencoded space — interleaved_space arrives as `A+K+I+A+…`.
        let query_interleaved = format!(
            "https://evil.com/?q={}",
            raw.chars()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("+")
        );
        assert!(
            s.scan_uri(&query_interleaved, "evil.com")
                .iter()
                .any(|v| v.detector == aws),
            "interleaved-space (form-encoded `+`) in URI query should be detected"
        );

        let query_ascii85 = format!("https://evil.com/?q={}", ascii85_enc(raw.as_bytes()));
        assert!(
            s.scan_uri(&query_ascii85, "evil.com")
                .iter()
                .any(|v| v.detector == aws),
            "ascii85 in URI query should be detected"
        );

        // --- JSON body exfil ---
        let json_ascii85 = format!(r#"{{"token":"{}"}}"#, ascii85_enc(raw.as_bytes()));
        assert!(
            s.scan_body(json_ascii85.as_bytes(), None, "evil.com")
                .iter()
                .any(|v| v.detector == aws),
            "ascii85 in JSON body should be detected"
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

    // =================================================================
    // Response-direction tests.
    //
    // Before this PR, response scanning was a substring check on the
    // body only. These tests pin the new contract: every reflective
    // exfil channel an upstream could use is covered, including the
    // ones the old scan would have missed (Set-Cookie / Location /
    // canary embedded in a JSON value with attribution).
    // =================================================================

    fn canary_scanner_with(canary: &str) -> DlpScanner {
        DlpScanner::new(vec![canary.to_string()], &HashMap::new(), 32, true, false)
            .expect("scanner")
    }

    #[test]
    fn response_scan_catches_canary_echo_in_set_cookie() {
        // A malicious upstream returns the session canary back in a
        // Set-Cookie header — the previous body-only scan missed
        // this entirely.
        let canary = "CANISTERTOKEN1234567890ABCDEF";
        let s = canary_scanner_with(canary);
        let headers = vec![(
            "Set-Cookie".to_string(),
            format!("session={canary}; Path=/"),
        )];
        let verdicts = s.scan_response(&headers, b"", Some("text/plain"), None, "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector.as_str() == "canary_token"),
            "canary echoed in Set-Cookie must fire"
        );
        assert!(
            verdicts.iter().any(|v| matches!(
                v.source.as_ref(),
                Some(StringSource::HeaderValue { name }) if name.eq_ignore_ascii_case("set-cookie")
            )),
            "source must attribute the Set-Cookie header"
        );
    }

    #[test]
    fn response_scan_catches_canary_in_location_redirect() {
        // 302 redirect pointing at attacker-controlled URL with the
        // canary in the query string.
        let canary = "CANISTERTOKEN1234567890ABCDEF";
        let s = canary_scanner_with(canary);
        let headers = vec![(
            "Location".to_string(),
            format!("https://attacker.test/r?t={canary}"),
        )];
        let verdicts = s.scan_response(&headers, b"", Some("text/plain"), None, "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector.as_str() == "canary_token"),
            "canary in Location must fire"
        );
    }

    #[test]
    fn response_scan_catches_base64_canary_in_json_response() {
        // Canary base64-encoded inside a nested JSON string. The old
        // body-only scan caught the base64 via decode_layers but
        // produced no attribution; the new path emits a verdict whose
        // source points at the exact JSON path.
        let canary = "CANISTERTOKEN1234567890ABCDEF";
        let s = canary_scanner_with(canary);
        let b64 = base64::engine::general_purpose::STANDARD.encode(canary);
        let body = format!(r#"{{"meta":{{"echo":"{b64}"}}}}"#);
        let verdicts = s.scan_response(
            &[],
            body.as_bytes(),
            Some("application/json"),
            None,
            "evil.com",
        );
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector.as_str() == "canary_token"),
            "base64-wrapped canary in JSON body must fire"
        );
        assert!(
            verdicts.iter().any(|v| matches!(
                v.source.as_ref(),
                Some(StringSource::JsonString { path }) if path.contains("echo")
            )),
            "source must attribute the JSON path of the leak"
        );
    }

    #[test]
    fn response_scan_catches_separator_obfuscated_canary() {
        // Upstream reflects the canary with `-` interleaved. The old
        // substring matcher missed this; the new path runs the same
        // strip_separators normalize pass as the request side.
        let canary = "CANISTERTOKEN1234567890ABCDEF";
        let s = canary_scanner_with(canary);
        let interleaved: String = canary
            .chars()
            .enumerate()
            .flat_map(|(i, c)| if i == 0 { vec![c] } else { vec!['-', c] })
            .collect();
        let body = format!("echo={interleaved}");
        let verdicts = s.scan_response(&[], body.as_bytes(), Some("text/plain"), None, "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector.as_str() == "canary_token"),
            "interleaved-separator canary in body must fire after normalize"
        );
    }

    // =================================================================
    // Hostile-payload scanner tests — these payloads were bypassing
    // detection before PR4 because the scanner only walked JSON for
    // structured bodies and ignored trailers entirely. Each test
    // pins one previously-vulnerable channel.
    // =================================================================

    #[test]
    fn scan_request_catches_credential_in_trailer() {
        let s = scanner();
        let token = format!("ghp_{}", "T".repeat(36));
        let trailers = vec![("X-Sig".to_string(), token)];
        let verdicts = s.scan_trailers(&trailers, "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat")),
            "credential in HTTP/1.1 chunked trailer must fire"
        );
        assert!(
            verdicts.iter().any(|v| matches!(
                v.source.as_ref(),
                Some(StringSource::TrailerValue { name }) if name == "X-Sig"
            )),
            "verdict must attribute the trailer"
        );
    }

    #[test]
    fn scan_request_catches_credential_in_form_urlencoded_value() {
        let s = scanner();
        let token = format!("ghp_{}", "F".repeat(36));
        let body = format!("name=alice&token={token}&other=value");
        let verdicts = s.scan_body_with_type(
            body.as_bytes(),
            None,
            Some("application/x-www-form-urlencoded"),
            "evil.com",
        );
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat"))
        );
        assert!(
            verdicts.iter().any(|v| matches!(
                v.source.as_ref(),
                Some(StringSource::FormValue { key }) if key == "token"
            )),
            "verdict must attribute the form-urlencoded key"
        );
    }

    #[test]
    fn scan_request_catches_credential_in_multipart_part() {
        let s = scanner();
        let token = format!("ghp_{}", "M".repeat(36));
        let body = format!(
            "--xxxxxx\r\n\
             Content-Disposition: form-data; name=\"api_key\"\r\n\
             \r\n\
             {token}\r\n\
             --xxxxxx--\r\n"
        );
        let verdicts = s.scan_body_with_type(
            body.as_bytes(),
            None,
            Some("multipart/form-data; boundary=xxxxxx"),
            "evil.com",
        );
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat"))
        );
        assert!(
            verdicts.iter().any(|v| matches!(
                v.source.as_ref(),
                Some(StringSource::Multipart { field }) if field == "api_key"
            )),
            "verdict must attribute the multipart field"
        );
    }

    #[test]
    fn scan_request_catches_credential_in_xml_text_node() {
        let s = scanner();
        let token = format!("ghp_{}", "X".repeat(36));
        let body = format!("<Auth><Provider>github</Provider><Token>{token}</Token></Auth>");
        let verdicts =
            s.scan_body_with_type(body.as_bytes(), None, Some("application/xml"), "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat"))
        );
        assert!(
            verdicts.iter().any(|v| matches!(
                v.source.as_ref(),
                Some(StringSource::XmlText { path }) if path.ends_with("Token")
            )),
            "verdict must attribute the XML element path"
        );
    }

    #[test]
    fn scan_request_catches_credential_in_xml_attribute() {
        let s = scanner();
        let token = "AKIA1234567890ABCDEF";
        let body = format!("<Config api_key=\"{token}\" public=\"yes\"/>");
        let verdicts = s.scan_body_with_type(body.as_bytes(), None, Some("text/xml"), "evil.com");
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("aws_access_key"))
        );
        assert!(
            verdicts.iter().any(|v| matches!(
                v.source.as_ref(),
                Some(StringSource::XmlAttribute { name, .. }) if name == "api_key"
            )),
            "verdict must attribute the XML attribute"
        );
    }

    #[test]
    fn scan_request_catches_credential_in_stacked_content_encoding() {
        // gzip(deflate(payload)) sent on the wire as
        // `Content-Encoding: deflate, gzip`. The PR4 multi-layer
        // decompress unwraps both; the original single-layer match
        // would have left the gzip layer untouched.
        use std::io::Write;
        let s = scanner();
        let token = format!("ghp_{}", "S".repeat(36));
        let deflated = {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(token.as_bytes()).unwrap();
            e.finish().unwrap()
        };
        let stacked = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&deflated).unwrap();
            e.finish().unwrap()
        };
        let verdicts = s.scan_body_with_type(
            &stacked,
            Some("deflate, gzip"),
            Some("application/octet-stream"),
            "evil.com",
        );
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat")),
            "stacked Content-Encoding must unwrap both layers"
        );
    }

    #[test]
    fn scan_response_catches_canary_in_trailer() {
        let canary = "CANISTERTOKENRESPONSETRAILER0";
        let s = canary_scanner_with(canary);
        let trailers = vec![("X-Echo".to_string(), canary.to_string())];
        let verdicts = s.scan_response_with_trailers(
            &[],
            b"ok",
            Some("text/plain"),
            None,
            &trailers,
            "evil.com",
        );
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector.as_str() == "canary_token"),
            "canary reflected via response trailer must fire"
        );
        assert!(
            verdicts.iter().any(|v| matches!(
                v.source.as_ref(),
                Some(StringSource::TrailerValue { name }) if name == "X-Echo"
            )),
            "verdict must attribute the trailer"
        );
    }

    #[test]
    fn response_scan_catches_upstream_credential_leak() {
        // A misbehaving API returns an actual github_pat in its
        // response body — say, in an error message. The previous
        // canary-only scan would have happily forwarded this; the
        // full registry catches it.
        let s = scanner();
        let token = format!("ghp_{}", "Z".repeat(36));
        let body = format!(r#"{{"error":"invalid_token: {token}"}}"#);
        let verdicts = s.scan_response(
            &[],
            body.as_bytes(),
            Some("application/json"),
            None,
            "evil.com",
        );
        assert!(
            verdicts
                .iter()
                .any(|v| v.detector == DetectorId::new("github_pat")),
            "credential reflected by upstream must fire"
        );
    }
}
