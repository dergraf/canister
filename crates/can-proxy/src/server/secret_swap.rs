//! Fake-secret → real-secret swap on authorized egress.
//!
//! `[network.dlp] fake_secrets` gives the sandbox a *fake* credential
//! under the real env-var name (e.g. `GITHUB_TOKEN`) and hands the proxy a
//! `fake → real` map. This module substitutes the real value back in just
//! before the request is forwarded upstream — but only for requests bound
//! to a host the credential is authorized for
//! ([`DlpScanner::credential_allowed`]).
//!
//! The authorization check is the swap's own gate and is **independent of
//! enforcement mode**: in monitor mode an unauthorized request is no longer
//! blocked, but the swap still refuses to run, so the real secret never
//! reaches an unauthorized destination. A request the sandbox encrypts
//! before sending contains no recoverable `fake` substring, so nothing is
//! swapped and only the useless fake leaves.

use bytes::Bytes;
use hyper::HeaderMap;
use hyper::header::{HeaderName, HeaderValue};

use can_dlp::DlpScanner;

/// One fake→real substitution. `real` is sensitive and deliberately kept
/// out of `Debug` output and logs.
#[derive(Clone)]
pub struct SecretSwap {
    /// The fake value injected into the sandbox under the real env-var name.
    pub fake: String,
    /// The real host secret. Never logged.
    pub real: String,
    /// DLP detector id (e.g. `github_pat`) gating where the swap may occur.
    pub detector: String,
}

impl std::fmt::Debug for SecretSwap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretSwap")
            .field("detector", &self.detector)
            .field("real", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Substitute real values for fakes in header values, for swaps authorized
/// at `host`. Header values that don't round-trip through `HeaderValue`
/// after substitution are left untouched (fail safe: the fake stays).
pub(super) fn swap_in_headers(
    swaps: &[SecretSwap],
    scanner: &DlpScanner,
    host: &str,
    headers: &mut HeaderMap,
) {
    let authorized = authorized_swaps(swaps, scanner, host);
    if authorized.is_empty() {
        return;
    }
    let mut updates: Vec<(HeaderName, HeaderValue)> = Vec::new();
    for (name, value) in headers.iter() {
        let Ok(text) = value.to_str() else { continue };
        let mut new = text.to_string();
        let mut changed = false;
        for sw in &authorized {
            if new.contains(&sw.fake) {
                new = new.replace(&sw.fake, &sw.real);
                changed = true;
            }
        }
        if !changed {
            continue;
        }
        match HeaderValue::from_str(&new) {
            Ok(hv) => updates.push((name.clone(), hv)),
            Err(_) => tracing::warn!(
                header = %name,
                "secret swap produced an invalid header value; leaving fake in place"
            ),
        }
    }
    for (name, value) in updates {
        headers.insert(name, value);
    }
}

/// Substitute real values for fakes in a buffered request body, for swaps
/// authorized at `host`. Returns the (possibly rewritten) bytes; allocates
/// only when a swap actually matches.
pub(super) fn swap_in_body(
    swaps: &[SecretSwap],
    scanner: &DlpScanner,
    host: &str,
    bytes: Bytes,
) -> Bytes {
    let authorized = authorized_swaps(swaps, scanner, host);
    if authorized.is_empty() {
        return bytes;
    }
    let mut buf: Option<Vec<u8>> = None;
    for sw in &authorized {
        let current: &[u8] = buf.as_deref().unwrap_or(&bytes);
        if let Some(replaced) = replace_bytes(current, sw.fake.as_bytes(), sw.real.as_bytes()) {
            buf = Some(replaced);
        }
    }
    match buf {
        Some(v) => Bytes::from(v),
        None => bytes,
    }
}

fn authorized_swaps<'a>(
    swaps: &'a [SecretSwap],
    scanner: &DlpScanner,
    host: &str,
) -> Vec<&'a SecretSwap> {
    swaps
        .iter()
        .filter(|s| scanner.credential_allowed(&s.detector, host))
        .collect()
}

/// Replace every non-overlapping occurrence of `needle` in `haystack` with
/// `replacement`. Returns `None` when `needle` is absent (no allocation).
fn replace_bytes(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let mut matches = Vec::new();
    let mut idx = 0;
    while idx + needle.len() <= haystack.len() {
        if &haystack[idx..idx + needle.len()] == needle {
            matches.push(idx);
            idx += needle.len();
        } else {
            idx += 1;
        }
    }
    if matches.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut last = 0;
    for m in matches {
        out.extend_from_slice(&haystack[last..m]);
        out.extend_from_slice(replacement);
        last = m + needle.len();
    }
    out.extend_from_slice(&haystack[last..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn swap(fake: &str, real: &str, detector: &str) -> SecretSwap {
        SecretSwap {
            fake: fake.to_string(),
            real: real.to_string(),
            detector: detector.to_string(),
        }
    }

    #[test]
    fn replace_bytes_substitutes_all_occurrences() {
        let out = replace_bytes(b"a-FAKE-b-FAKE", b"FAKE", b"REAL").unwrap();
        assert_eq!(out, b"a-REAL-b-REAL");
    }

    #[test]
    fn replace_bytes_absent_needle_returns_none() {
        assert!(replace_bytes(b"nothing here", b"FAKE", b"REAL").is_none());
    }

    #[test]
    fn replace_bytes_length_changing_replacement() {
        let out = replace_bytes(b"x=FAKE", b"FAKE", b"REALER_VALUE").unwrap();
        assert_eq!(out, b"x=REALER_VALUE");
    }

    #[test]
    fn header_swap_authorized_host_replaces_value() {
        let scanner = DlpScanner::new(vec![], &Default::default(), 32, true, false).unwrap();
        // `ghp_…` (github_pat) is authorized at its home domain github.com.
        let fake = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let real = "ghp_RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";
        let swaps = vec![swap(fake, real, "github_pat")];
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {fake}")).unwrap(),
        );
        swap_in_headers(&swaps, &scanner, "github.com", &mut headers);
        assert_eq!(
            headers.get(hyper::header::AUTHORIZATION).unwrap(),
            &format!("Bearer {real}")
        );
    }

    #[test]
    fn header_swap_unauthorized_host_leaves_fake() {
        let scanner = DlpScanner::new(vec![], &Default::default(), 32, true, false).unwrap();
        let fake = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let real = "ghp_RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";
        let swaps = vec![swap(fake, real, "github_pat")];
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {fake}")).unwrap(),
        );
        // evil.example.com is not a github_pat home domain and has no scope.
        swap_in_headers(&swaps, &scanner, "evil.example.com", &mut headers);
        assert_eq!(
            headers.get(hyper::header::AUTHORIZATION).unwrap(),
            &format!("Bearer {fake}"),
            "real secret must not be swapped in for an unauthorized host"
        );
    }

    #[test]
    fn body_swap_only_when_authorized() {
        let scanner = DlpScanner::new(vec![], &Default::default(), 32, true, false).unwrap();
        let fake = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let real = "ghp_RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";
        let swaps = vec![swap(fake, real, "github_pat")];
        let body = Bytes::from(format!("{{\"token\":\"{fake}\"}}"));

        let allowed = swap_in_body(&swaps, &scanner, "github.com", body.clone());
        assert!(allowed.windows(real.len()).any(|w| w == real.as_bytes()));

        let denied = swap_in_body(&swaps, &scanner, "evil.example.com", body.clone());
        assert_eq!(denied, body, "no swap at unauthorized host");
    }

    #[test]
    fn body_swap_absent_fake_is_noop() {
        let scanner = DlpScanner::new(vec![], &Default::default(), 32, true, false).unwrap();
        let swaps = vec![swap(
            "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ghp_RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR",
            "github_pat",
        )];
        let body = Bytes::from_static(b"no secret here");
        let out = swap_in_body(&swaps, &scanner, "github.com", body.clone());
        assert_eq!(out, body);
    }
}
