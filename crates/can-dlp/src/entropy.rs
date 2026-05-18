use std::sync::atomic::{AtomicU64, Ordering};

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

pub fn high_entropy_byte_count(data: &[u8], window: usize, threshold: f64) -> u64 {
    if data.len() < window {
        let e = shannon_entropy(data);
        return if e > threshold { data.len() as u64 } else { 0 };
    }

    let mut count = 0u64;
    let mut i = 0;
    while i + window <= data.len() {
        let e = shannon_entropy(&data[i..i + window]);
        if e > threshold {
            count += window as u64;
            i += window;
        } else {
            i += 1;
        }
    }
    count
}

/// Detect chunked DNS exfiltration by looking for high per-character entropy
/// in hostname labels.
///
/// The earlier implementation used a `len >= 8` floor with an absolute Shannon
/// threshold (default 4.0 bits/char). That is *intrinsically* uncatchable for
/// short labels: the Shannon entropy of any string of length L over an
/// alphabet of size A is bounded by `min(log2(L), log2(A))`. A 7-character
/// label maxes out at `log2(7) ≈ 2.81` bits, so a base32-chunked exfil like
/// `qx7vw2k.j9p3rmn.b8tczh4.attacker.com` passed every label silently (F2).
///
/// The replacement compares each label's entropy to its per-length maximum
/// and treats the result as a *normalised* ratio in `[0.0, 1.0]`. A label is
/// "random-looking" when:
///   - its length is at least 4 (under 4 chars Shannon entropy is noise),
///   - it does not look like a natural English word (mixed letters with both
///     vowels and consonants — catches `compute`, `amazonaws`, etc.), and
///   - its normalised entropy exceeds `threshold` (default 0.92).
///
/// The FQDN trips if *two or more* labels are random-looking — that is the
/// signature of chunked exfiltration. A single random-looking 8-char label
/// (e.g., an AWS-style instance subdomain) does not trip on its own.
///
/// `threshold` is interpreted as a normalised ratio. Values >1.0 are clamped
/// to 1.0 (defensive: pre-redesign configs used bits — those configs now
/// effectively disable the check, which fails open).
pub fn dns_label_entropy(hostname: &str, threshold: f64) -> bool {
    let ratio = if threshold > 1.0 { 1.0 } else { threshold };
    let suspicious = hostname
        .split('.')
        .filter(|label| label_looks_random(label, ratio))
        .count();
    suspicious >= 2
}

fn label_looks_random(label: &str, ratio_threshold: f64) -> bool {
    if label.len() < 4 {
        return false;
    }
    if looks_like_natural_word(label) {
        return false;
    }
    let max = (label.len() as f64).log2();
    if max <= 0.0 {
        return false;
    }
    let entropy = shannon_entropy(label.as_bytes());
    (entropy / max) > ratio_threshold
}

fn looks_like_natural_word(label: &str) -> bool {
    let bytes = label.as_bytes();
    if !bytes.iter().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let has_vowel = bytes.iter().any(|b| {
        matches!(
            b.to_ascii_lowercase(),
            b'a' | b'e' | b'i' | b'o' | b'u' | b'y'
        )
    });
    let has_consonant = bytes.iter().any(|b| {
        b.is_ascii_alphabetic()
            && !matches!(
                b.to_ascii_lowercase(),
                b'a' | b'e' | b'i' | b'o' | b'u' | b'y'
            )
    });
    has_vowel && has_consonant
}

pub struct SessionEntropyBudget {
    budget_bytes: u64,
    used: AtomicU64,
}

impl SessionEntropyBudget {
    pub fn new(budget_bytes: u64) -> Self {
        Self {
            budget_bytes,
            used: AtomicU64::new(0),
        }
    }

    pub fn record(&self, high_entropy_bytes: u64) -> bool {
        let prev = self.used.fetch_add(high_entropy_bytes, Ordering::Relaxed);
        prev + high_entropy_bytes <= self.budget_bytes
    }

    pub fn exceeded(&self) -> bool {
        self.used.load(Ordering::Relaxed) > self.budget_bytes
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn budget(&self) -> u64 {
        self.budget_bytes
    }
}

/// Per-destination budget table. Each unique host gets its own
/// `SessionEntropyBudget`, so a noisy or hostile destination can't
/// poison the budget for unrelated traffic.
///
/// The previous single-counter design (F7 in the DLP plan) had two
/// problems: (1) an attacker paced low-entropy requests across many
/// destinations to stay under the global budget; (2) a legitimate upload
/// of one large random-looking artifact (model weights, encrypted
/// archive) tripped the budget and blocked subsequent traffic to
/// completely different hosts. Per-host isolates both pathologies.
pub struct PerHostEntropyBudget {
    per_host_budget_bytes: u64,
    table: std::sync::Mutex<std::collections::HashMap<String, SessionEntropyBudget>>,
}

impl PerHostEntropyBudget {
    pub fn new(per_host_budget_bytes: u64) -> Self {
        Self {
            per_host_budget_bytes,
            table: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record `high_entropy_bytes` against `host`'s budget. Returns
    /// `true` if the host is still under budget, `false` if it has just
    /// crossed it. A first-time host gets a fresh budget initialised
    /// from `per_host_budget_bytes`.
    pub fn record(&self, host: &str, high_entropy_bytes: u64) -> bool {
        let mut tbl = self
            .table
            .lock()
            .expect("per-host entropy budget mutex poisoned");
        let entry = tbl
            .entry(host.to_string())
            .or_insert_with(|| SessionEntropyBudget::new(self.per_host_budget_bytes));
        entry.record(high_entropy_bytes)
    }

    pub fn used(&self, host: &str) -> u64 {
        self.table
            .lock()
            .expect("per-host entropy budget mutex poisoned")
            .get(host)
            .map(|b| b.used())
            .unwrap_or(0)
    }

    pub fn budget(&self) -> u64 {
        self.per_host_budget_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros() {
        let data = vec![0u8; 100];
        assert!(shannon_entropy(&data) < 0.01);
    }

    #[test]
    fn entropy_of_random_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!(
            e > 7.9,
            "uniform distribution should have ~8.0 bits, got {e}"
        );
    }

    #[test]
    fn entropy_of_repeated_char() {
        let data = b"aaaaaaaaaaaaaaaaaaa";
        assert!(shannon_entropy(data) < 0.01);
    }

    #[test]
    fn entropy_of_hex_string() {
        let hex = "4a6f686e446f654031323334353637383930";
        let e = shannon_entropy(hex.as_bytes());
        assert!(e > 3.0, "hex strings have moderate entropy, got {e}");
    }

    #[test]
    fn entropy_empty_input() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    // The threshold here is a normalised ratio (0.0–1.0), not absolute bits.
    // 0.92 matches the production default.

    #[test]
    fn dns_label_high_entropy_long_label_alone_does_not_trip() {
        // One long random-looking label is *not* enough to trip; many AWS
        // hostnames look this way (e.g., `i-0a3b8c9.compute.amazonaws.com`).
        assert!(!dns_label_entropy(
            "a3f8b2c1e9d4z7x5y6w0.attacker.com",
            0.92
        ));
    }

    #[test]
    fn dns_label_normal_hostnames_pass() {
        assert!(!dns_label_entropy("www.google.com", 0.92));
        assert!(!dns_label_entropy("api.github.com", 0.92));
        assert!(!dns_label_entropy(
            "lb-x42abc7d8.us-east-1.amazonaws.com",
            0.92
        ));
        assert!(!dns_label_entropy("i-0a3b8c9.compute.amazonaws.com", 0.92));
    }

    #[test]
    fn dns_label_short_labels_skipped() {
        assert!(!dns_label_entropy("ab.cd.ef", 0.92));
    }

    #[test]
    fn dns_label_short_chunks_chained_trip() {
        // F2 regression: chunked exfil with 7-char labels used to bypass the
        // `len >= 8` floor entirely. Normalised entropy across multiple
        // labels now catches the chain.
        assert!(dns_label_entropy(
            "qx7vw2k.j9p3rmn.b8tczh4.attacker.com",
            0.92
        ));
    }

    #[test]
    fn dns_label_zero_entropy_chains_do_not_trip() {
        // Each label is all the same char — Shannon entropy is 0, not high.
        // (Real exfil wouldn't use repeated chars, but the heuristic must
        // not false-positive on contrived inputs either.)
        assert!(!dns_label_entropy(
            "aaaaaaa.bbbbbbb.ccccccc.attacker.com",
            0.92
        ));
    }

    #[test]
    fn dns_label_legacy_bits_value_fails_open() {
        // Configs predating the redesign passed `4.0` (bits). Clamping to
        // 1.0 makes the check effectively never fire — fail-open, with
        // the redesign note in the config doc explaining the migration.
        assert!(!dns_label_entropy(
            "qx7vw2k.j9p3rmn.b8tczh4.attacker.com",
            4.0
        ));
    }

    #[test]
    fn dns_label_natural_words_skipped() {
        // `compute` and `amazonaws` are 7- and 9-char labels with near-max
        // normalised entropy (all unique chars). The natural-word filter
        // (mixed vowels + consonants, alpha-only) skips them so the chain
        // doesn't trip.
        assert!(!dns_label_entropy("compute.amazonaws.com", 0.92));
    }

    #[test]
    fn session_budget_basic() {
        let budget = SessionEntropyBudget::new(100);
        assert!(budget.record(50));
        assert!(!budget.exceeded());
        assert!(budget.record(50));
        assert!(!budget.exceeded());
        budget.record(1);
        assert!(budget.exceeded());
    }

    #[test]
    fn session_budget_single_overflow() {
        let budget = SessionEntropyBudget::new(100);
        assert!(!budget.record(200));
        assert!(budget.exceeded());
    }

    #[test]
    fn high_entropy_byte_count_low_entropy() {
        let data = vec![b'a'; 200];
        assert_eq!(high_entropy_byte_count(&data, 32, 4.0), 0);
    }

    #[test]
    fn high_entropy_byte_count_high_entropy() {
        let data: Vec<u8> = (0..=255).cycle().take(256).collect();
        let count = high_entropy_byte_count(&data, 32, 4.0);
        assert!(count > 0, "random-ish data should have high entropy bytes");
    }

    #[test]
    fn per_host_budget_isolates_destinations() {
        // R9: exhausting the budget for one host must not affect another.
        let budget = PerHostEntropyBudget::new(100);
        assert!(budget.record("a.example.com", 100));
        // Pushing 'a' over the budget returns false.
        assert!(!budget.record("a.example.com", 1));
        // 'b' should still have a full budget.
        assert!(budget.record("b.example.com", 100));
        assert_eq!(budget.used("a.example.com"), 101);
        assert_eq!(budget.used("b.example.com"), 100);
        assert_eq!(budget.used("c.never.seen"), 0);
    }

    #[test]
    fn per_host_budget_per_host_independent_overflow() {
        // A single overflowing request on one host doesn't poison
        // others, even if the overflow itself exceeds the budget.
        let budget = PerHostEntropyBudget::new(100);
        assert!(!budget.record("noisy.example.com", 200));
        assert!(budget.record("clean.example.com", 50));
    }
}
