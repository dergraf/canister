use sha2::{Digest, Sha256};

/// Render a token-like string so it is safe to ship to logs / SIEM.
///
/// The output keeps the first 4 ASCII chars as a context prefix (just enough
/// to tell `ghp_…` from `sk-ant-…`), then a fixed mask, then an 8-hex-digit
/// SHA-256 prefix so two log lines for the same secret can be correlated
/// without exposing the secret. The full length is appended so a reader can
/// see at a glance whether this is a 40-char PAT or a 4-char fragment.
///
/// `redact("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")` →
/// `"ghp_•••••5b40e3f1 (len=40)"`.
///
/// Non-ASCII inputs lose their prefix (replaced with `••••`) but the
/// hash/length still serve as a fingerprint.
pub fn redact(matched: &str) -> String {
    let len = matched.chars().count();
    let prefix: String = matched
        .chars()
        .take(4)
        .map(|c| if c.is_ascii_graphic() { c } else { '•' })
        .collect();

    let mut hasher = Sha256::new();
    hasher.update(matched.as_bytes());
    let digest = hasher.finalize();
    let hex8: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();

    format!("{prefix}•••••{hex8} (len={len})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_keeps_short_prefix() {
        let token = format!("ghp_{}", "A".repeat(36));
        let r = redact(&token);
        assert!(r.starts_with("ghp_"), "expected ghp_ prefix, got {r}");
        assert!(r.contains("(len=40)"));
    }

    #[test]
    fn redact_never_contains_full_token() {
        // The key invariant: a log line containing redact(token) must never
        // contain the original secret.
        let token = "ghp_BCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd";
        let r = redact(token);
        // Strip the leading 4-char prefix and verify nothing else of the
        // token (any 8-char substring after position 4) appears in r.
        for i in 4..(token.len() - 8) {
            let chunk = &token[i..i + 8];
            assert!(
                !r.contains(chunk),
                "redacted output leaks substring {chunk}: {r}"
            );
        }
    }

    #[test]
    fn redact_is_deterministic() {
        let token = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(redact(token), redact(token));
    }

    #[test]
    fn redact_differentiates_distinct_tokens() {
        let a = format!("ghp_{}", "A".repeat(36));
        let b = format!("ghp_{}", "B".repeat(36));
        assert_ne!(redact(&a), redact(&b));
    }

    #[test]
    fn redact_short_input_does_not_panic() {
        let _ = redact("");
        let _ = redact("ab");
        let _ = redact("a");
    }

    #[test]
    fn redact_handles_unicode_prefix() {
        let token = "α\u{200B}_secret_value_long_enough";
        // The Cyrillic / zero-width chars get replaced with `•`, but the
        // function must not panic and the hash must still be stable.
        let r = redact(token);
        assert!(r.contains("(len="));
    }

    #[test]
    fn redact_length_reflects_chars_not_bytes() {
        let token = "αβγδε";
        let r = redact(token);
        assert!(r.contains("(len=5)"), "expected char count 5: {r}");
    }
}
