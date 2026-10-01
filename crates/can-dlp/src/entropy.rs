use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, RandomState};
use std::ops::Range;
use std::sync::Mutex;
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

/// Window size and per-window Shannon threshold of the session entropy
/// budget: a 32-byte window above 4.0 bits counts as high-entropy.
pub const BUDGET_WINDOW: usize = 32;
pub const BUDGET_THRESHOLD: f64 = 4.0;

pub fn high_entropy_byte_count(data: &[u8], window: usize, threshold: f64) -> u64 {
    high_entropy_windows(data, window, threshold)
        .iter()
        .map(|w| w.len() as u64)
        .sum()
}

/// The high-entropy windows of `data`, in order and non-overlapping.
///
/// The scan slides one byte at a time through low-entropy data and jumps a
/// whole window past a hit, so each byte belongs to at most one window.
/// Data shorter than `window` is judged as a whole.
pub fn high_entropy_windows(data: &[u8], window: usize, threshold: f64) -> Vec<Range<usize>> {
    if data.len() < window {
        return if !data.is_empty() && shannon_entropy(data) > threshold {
            std::iter::once(0..data.len()).collect()
        } else {
            Vec::new()
        };
    }

    let mut hits = Vec::new();
    let mut i = 0;
    while i + window <= data.len() {
        if shannon_entropy(&data[i..i + window]) > threshold {
            hits.push(i..i + window);
            i += window;
        } else {
            i += 1;
        }
    }
    hits
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

/// Upper bound on the window digests remembered per host, so a host that
/// is allowed a large budget cannot grow the table without limit. Past
/// it, nothing more is remembered and resent bytes are charged again,
/// which errs towards blocking.
pub const MAX_REMEMBERED_WINDOWS_PER_HOST: usize = 1 << 20;

/// Where a request body is going, as the session entropy budget sees it.
#[derive(Debug, Clone, Copy)]
pub struct EntropyDestination<'a> {
    /// The host whose budget the body is charged to.
    pub host: &'a str,
    /// Narrows "already delivered" below the host: a window counts as
    /// delivered only if it was sent to `host` under the same scope. The
    /// proxy uses the request target and the credential headers, so a
    /// second account or endpoint on one host is charged afresh.
    pub scope: &'a str,
    /// Budget for this host; `None` uses the session default.
    pub budget_override: Option<u64>,
}

/// The outcome of charging one request body to its host's budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyCharge {
    /// High-entropy bytes in the body the host had not been sent before.
    pub charged: u64,
    /// The host's running total after this charge.
    pub used: u64,
    /// The budget the total is held against.
    pub budget: u64,
}

impl EntropyCharge {
    /// A body that adds nothing new always passes, even on an exhausted
    /// budget, as a body without high-entropy bytes always has.
    pub fn within_budget(&self) -> bool {
        self.charged == 0 || self.used <= self.budget
    }
}

#[derive(Default)]
struct HostLedger {
    used: u64,
    /// Keyed digests of every high-entropy window delivered to the host,
    /// at every byte offset, so a resent run matches however it is aligned.
    delivered: HashSet<u64>,
}

/// Per-destination budget table. Each unique host gets its own running
/// total, so a noisy or hostile destination can't poison the budget for
/// unrelated traffic.
///
/// The previous single-counter design (F7 in the DLP plan) had two
/// problems: (1) an attacker paced low-entropy requests across many
/// destinations to stay under the global budget; (2) a legitimate upload
/// of one large random-looking artifact (model weights, encrypted
/// archive) tripped the budget and blocked subsequent traffic to
/// completely different hosts. Per-host isolates both pathologies.
///
/// [`Self::charge`] counts each high-entropy window once per host and
/// scope: a window the host was already sent is not charged again. A tool
/// loop resends the whole conversation on every turn, and charging the
/// history again made the total grow with the square of the turn count
/// (ADR-0020).
pub struct PerHostEntropyBudget {
    per_host_budget_bytes: u64,
    remember_cap: usize,
    digest_keys: RandomState,
    table: Mutex<HashMap<String, HostLedger>>,
}

impl PerHostEntropyBudget {
    pub fn new(per_host_budget_bytes: u64) -> Self {
        Self {
            per_host_budget_bytes,
            remember_cap: MAX_REMEMBERED_WINDOWS_PER_HOST,
            digest_keys: RandomState::new(),
            table: Mutex::new(HashMap::new()),
        }
    }

    /// Record `high_entropy_bytes` against `host`'s budget without
    /// deduplication. Returns `true` if the host is still under budget,
    /// `false` if it has crossed it.
    pub fn record(&self, host: &str, high_entropy_bytes: u64) -> bool {
        let mut table = self.lock();
        let ledger = table.entry(host.to_string()).or_default();
        ledger.used = ledger.used.saturating_add(high_entropy_bytes);
        ledger.used <= self.per_host_budget_bytes
    }

    /// Charge the high-entropy windows of `body` that `dest` has not
    /// already been sent. When the result is within budget the body's
    /// windows are remembered as delivered; a refused body is not, since
    /// it never reached the host.
    pub fn charge(&self, dest: &EntropyDestination<'_>, body: &[u8]) -> EntropyCharge {
        let budget = dest.budget_override.unwrap_or(self.per_host_budget_bytes);
        let hits = high_entropy_windows(body, BUDGET_WINDOW, BUDGET_THRESHOLD);
        let digests: Vec<u64> = hits
            .iter()
            .map(|w| self.digest(dest.scope, &body[w.clone()]))
            .collect();

        let (charge, fresh) = {
            let mut table = self.lock();
            let ledger = table.entry(dest.host.to_string()).or_default();
            let fresh: Vec<bool> = digests
                .iter()
                .map(|d| !ledger.delivered.contains(d))
                .collect();
            let charged: u64 = hits
                .iter()
                .zip(&fresh)
                .filter(|(_, is_fresh)| **is_fresh)
                .map(|(w, _)| w.len() as u64)
                .sum();
            ledger.used = ledger.used.saturating_add(charged);
            let charge = EntropyCharge {
                charged,
                used: ledger.used,
                budget,
            };
            (charge, fresh)
        };

        if charge.charged > 0 && charge.within_budget() {
            let delivered = self.delivered_digests(dest.scope, body, &hits, &fresh);
            let mut table = self.lock();
            let ledger = table.entry(dest.host.to_string()).or_default();
            for digest in delivered {
                if ledger.delivered.len() >= self.remember_cap {
                    break;
                }
                ledger.delivered.insert(digest);
            }
        }
        charge
    }

    pub fn used(&self, host: &str) -> u64 {
        self.lock().get(host).map(|l| l.used).unwrap_or(0)
    }

    pub fn budget(&self) -> u64 {
        self.per_host_budget_bytes
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, HostLedger>> {
        // SAFETY-UNWRAP: the code under this mutex is HashMap/HashSet
        // bookkeeping with no panic path, so the mutex can't be poisoned.
        self.table
            .lock()
            .expect("per-host entropy budget mutex poisoned")
    }

    fn digest(&self, scope: &str, window: &[u8]) -> u64 {
        self.digest_keys.hash_one((scope, window))
    }

    /// Digests of every window-sized slice, at every offset, of each run
    /// of adjacent hits that holds at least one fresh window. A run made
    /// only of already-delivered windows is skipped: its windows are on
    /// record, and any slice straddling two of them that is not stays
    /// chargeable, which errs towards blocking.
    fn delivered_digests(
        &self,
        scope: &str,
        body: &[u8],
        hits: &[Range<usize>],
        fresh: &[bool],
    ) -> Vec<u64> {
        let mut digests = Vec::new();
        for run in runs_of_adjacent_hits(hits, fresh) {
            if run.len() < BUDGET_WINDOW {
                digests.push(self.digest(scope, &body[run]));
                continue;
            }
            for start in run.start..=run.end - BUDGET_WINDOW {
                digests.push(self.digest(scope, &body[start..start + BUDGET_WINDOW]));
            }
        }
        digests
    }
}

/// Merge adjacent hit windows into runs, keeping the runs that contain at
/// least one fresh window.
fn runs_of_adjacent_hits(hits: &[Range<usize>], fresh: &[bool]) -> Vec<Range<usize>> {
    let mut runs: Vec<(Range<usize>, bool)> = Vec::new();
    for (window, &is_fresh) in hits.iter().zip(fresh) {
        match runs.last_mut() {
            Some((run, any_fresh)) if run.end == window.start => {
                run.end = window.end;
                *any_fresh |= is_fresh;
            }
            _ => runs.push((window.clone(), is_fresh)),
        }
    }
    runs.into_iter()
        .filter(|(_, any_fresh)| *any_fresh)
        .map(|(run, _)| run)
        .collect()
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

    // ── Deduplicated charging (ADR-0020) ─────────────────────────────

    use base64::Engine;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    fn random_bytes(rng: &mut StdRng, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    fn dest(host: &str) -> EntropyDestination<'_> {
        EntropyDestination {
            host,
            scope: "/v1/messages\nx-api-key=sk-fake",
            budget_override: None,
        }
    }

    /// One assistant turn of a reasoning model: a ~1 KB signed thinking
    /// block that must be sent back unchanged, plus a tool call.
    fn thinking_turn(rng: &mut StdRng, turn: usize) -> String {
        let signature = base64::engine::general_purpose::STANDARD.encode(random_bytes(rng, 1024));
        format!(
            r#"{{"role":"assistant","content":[{{"type":"thinking","thinking":"Read the next file.","signature":"{signature}"}},{{"type":"tool_use","name":"read_file","input":{{"path":"src/module_{turn}.rs"}}}}]}},{{"role":"user","content":"ok"}},"#
        )
    }

    /// The request body of turn `n`: the whole history so far, resent.
    fn conversation(history: &[String]) -> Vec<u8> {
        format!(
            r#"{{"model":"reasoning","messages":[{{"role":"user","content":"Fix the failing test."}},{}]}}"#,
            history.concat()
        )
        .into_bytes()
    }

    fn tool_loop(turns: usize) -> Vec<Vec<u8>> {
        let mut rng = StdRng::seed_from_u64(20);
        let mut history = Vec::new();
        (0..turns)
            .map(|turn| {
                history.push(thinking_turn(&mut rng, turn));
                conversation(&history)
            })
            .collect()
    }

    const TURNS: usize = 20;
    const PROVIDER_BUDGET: u64 = 64 * 1024;

    #[test]
    fn a_tool_loop_resending_its_history_is_charged_once_per_turn() {
        let budget = PerHostEntropyBudget::new(PROVIDER_BUDGET);
        for (turn, body) in tool_loop(TURNS).iter().enumerate() {
            let charge = budget.charge(&dest("api.provider.example"), body);
            assert!(charge.within_budget(), "turn {turn} blocked: {charge:?}");
            // After the first request, which also carries the prompt, each
            // turn adds one ~1.4 KB base64 signature; only that, plus at most
            // a window of new context on either side, is charged.
            assert!(
                turn == 0 || charge.charged <= 1368 + 2 * BUDGET_WINDOW as u64,
                "turn {turn} charged {} bytes",
                charge.charged
            );
        }
        let used = budget.used("api.provider.example");
        assert!(used < 32 * 1024, "used {used} for {TURNS} turns");
    }

    #[test]
    fn the_same_tool_loop_exhausts_the_budget_when_history_is_counted_again() {
        // Proves the simulation exercises the quadratic growth: counting
        // every high-entropy byte of every body, as before, blocks it.
        let budget = PerHostEntropyBudget::new(PROVIDER_BUDGET);
        let blocked_at = tool_loop(TURNS).iter().position(|body| {
            let high = high_entropy_byte_count(body, BUDGET_WINDOW, BUDGET_THRESHOLD);
            !budget.record("api.provider.example", high)
        });
        assert!(
            matches!(blocked_at, Some(turn) if turn < TURNS),
            "expected a block, got {blocked_at:?}"
        );
    }

    #[test]
    fn new_signatures_alone_still_exhaust_the_default_budget() {
        // Deduplication removes the quadratic term, not the linear one:
        // under the 8 KiB default a reasoning model still needs a
        // per-host override within its first dozen turns.
        let budget = PerHostEntropyBudget::new(8192);
        let blocked_at = tool_loop(TURNS).iter().position(|body| {
            !budget
                .charge(&dest("api.provider.example"), body)
                .within_budget()
        });
        assert!(
            matches!(blocked_at, Some(turn) if (4..12).contains(&turn)),
            "expected a block between turns 4 and 11, got {blocked_at:?}"
        );
    }

    #[test]
    fn new_high_entropy_data_exhausts_the_budget_at_the_boundary() {
        // 1 KiB of random bytes is 1 KiB of high-entropy windows, so an
        // 8 KiB budget admits exactly eight fresh blobs.
        let mut rng = StdRng::seed_from_u64(7);
        let budget = PerHostEntropyBudget::new(8 * 1024);
        for n in 1..=8 {
            let charge = budget.charge(&dest("evil.example"), &random_bytes(&mut rng, 1024));
            assert_eq!(charge.charged, 1024);
            assert!(charge.within_budget(), "blob {n} blocked: {charge:?}");
        }
        let ninth = budget.charge(&dest("evil.example"), &random_bytes(&mut rng, 1024));
        assert_eq!(ninth.used, 9 * 1024);
        assert!(!ninth.within_budget());
    }

    #[test]
    fn a_resent_body_is_free_wherever_it_is_aligned() {
        let mut rng = StdRng::seed_from_u64(1);
        let secret = random_bytes(&mut rng, 4096);
        let budget = PerHostEntropyBudget::new(1 << 20);
        assert_eq!(budget.charge(&dest("h.example"), &secret).charged, 4096);

        for shift in [1usize, 7, 31, 33] {
            let mut shifted = b"x".repeat(shift);
            shifted.extend_from_slice(&secret);
            let charge = budget.charge(&dest("h.example"), &shifted);
            assert!(
                charge.charged <= 2 * BUDGET_WINDOW as u64,
                "shift {shift} charged {}",
                charge.charged
            );
        }
    }

    #[test]
    fn a_part_of_a_delivered_body_is_free() {
        let mut rng = StdRng::seed_from_u64(2);
        let secret = random_bytes(&mut rng, 2048);
        let budget = PerHostEntropyBudget::new(1 << 20);
        budget.charge(&dest("h.example"), &secret);
        let charge = budget.charge(&dest("h.example"), &secret[500..1500]);
        assert_eq!(charge.charged, 0);
    }

    #[test]
    fn a_resent_body_is_charged_again_at_another_host() {
        let mut rng = StdRng::seed_from_u64(3);
        let secret = random_bytes(&mut rng, 1024);
        let budget = PerHostEntropyBudget::new(1 << 20);
        budget.charge(&dest("a.example"), &secret);
        assert_eq!(budget.charge(&dest("b.example"), &secret).charged, 1024);
    }

    #[test]
    fn a_resent_body_is_charged_again_under_another_scope() {
        // Another account or endpoint on the same host has not seen it.
        let mut rng = StdRng::seed_from_u64(4);
        let secret = random_bytes(&mut rng, 1024);
        let budget = PerHostEntropyBudget::new(1 << 20);
        budget.charge(&dest("h.example"), &secret);
        let other_account = EntropyDestination {
            scope: "/gists\nauthorization=token attacker",
            ..dest("h.example")
        };
        assert_eq!(budget.charge(&other_account, &secret).charged, 1024);
    }

    #[test]
    fn a_refused_body_is_not_remembered_as_delivered() {
        let mut rng = StdRng::seed_from_u64(5);
        let secret = random_bytes(&mut rng, 1024);
        let budget = PerHostEntropyBudget::new(512);
        assert!(!budget.charge(&dest("h.example"), &secret).within_budget());
        let retry = budget.charge(&dest("h.example"), &secret);
        assert_eq!(retry.charged, 1024);
        assert!(!retry.within_budget());
    }

    #[test]
    fn a_delivered_body_resent_after_exhaustion_passes_but_new_data_does_not() {
        let mut rng = StdRng::seed_from_u64(6);
        let delivered = random_bytes(&mut rng, 1024);
        let budget = PerHostEntropyBudget::new(1024);
        assert!(
            budget
                .charge(&dest("h.example"), &delivered)
                .within_budget()
        );
        assert!(
            !budget
                .charge(&dest("h.example"), &random_bytes(&mut rng, 64))
                .within_budget()
        );
        let resend = budget.charge(&dest("h.example"), &delivered);
        assert_eq!(resend.charged, 0);
        assert!(resend.within_budget());
    }

    #[test]
    fn repeats_within_one_body_are_each_charged() {
        let mut rng = StdRng::seed_from_u64(8);
        let secret = random_bytes(&mut rng, 256);
        let body = [
            secret.as_slice(),
            b"----------------------------------------",
            &secret,
        ]
        .concat();
        let budget = PerHostEntropyBudget::new(1 << 20);
        assert_eq!(budget.charge(&dest("h.example"), &body).charged, 512);
    }

    #[test]
    fn past_the_remember_cap_resent_bytes_are_charged_again() {
        let mut rng = StdRng::seed_from_u64(9);
        let secret = random_bytes(&mut rng, 1024);
        let mut budget = PerHostEntropyBudget::new(1 << 20);
        budget.remember_cap = 0;
        budget.charge(&dest("h.example"), &secret);
        assert_eq!(budget.charge(&dest("h.example"), &secret).charged, 1024);
    }

    #[test]
    fn the_remember_cap_bounds_the_digests_per_host() {
        let mut rng = StdRng::seed_from_u64(10);
        let mut budget = PerHostEntropyBudget::new(1 << 20);
        budget.remember_cap = 100;
        budget.charge(&dest("h.example"), &random_bytes(&mut rng, 4096));
        let remembered = budget.lock().get("h.example").map(|l| l.delivered.len());
        assert_eq!(remembered, Some(100));
    }

    #[test]
    fn a_short_body_is_judged_whole_and_remembered_whole() {
        let budget = PerHostEntropyBudget::new(1 << 20);
        let token = b"Zq8#kP2!vX7@mN4$wR9%tY3^"; // 24 distinct bytes, > 4 bits
        assert_eq!(budget.charge(&dest("h.example"), token).charged, 24);
        assert_eq!(budget.charge(&dest("h.example"), token).charged, 0);
    }

    #[test]
    fn a_low_entropy_body_charges_nothing() {
        let budget = PerHostEntropyBudget::new(10);
        let charge = budget.charge(&dest("h.example"), &[b'a'; 4096]);
        assert_eq!(charge.charged, 0);
        assert!(charge.within_budget());
        assert_eq!(budget.used("h.example"), 0);
    }

    #[test]
    fn the_override_replaces_the_default_budget_for_its_host() {
        let mut rng = StdRng::seed_from_u64(11);
        let budget = PerHostEntropyBudget::new(512);
        let provider = EntropyDestination {
            budget_override: Some(2048),
            ..dest("api.provider.example")
        };
        let charge = budget.charge(&provider, &random_bytes(&mut rng, 1024));
        assert_eq!(charge.budget, 2048);
        assert!(charge.within_budget());
        assert!(
            !budget
                .charge(&dest("other.example"), &random_bytes(&mut rng, 1024))
                .within_budget()
        );
    }

    /// The counter as it was before hit windows were exposed, kept to
    /// show the refactor did not change what is counted.
    fn legacy_count(data: &[u8], window: usize, threshold: f64) -> u64 {
        if data.len() < window {
            let e = shannon_entropy(data);
            return if e > threshold { data.len() as u64 } else { 0 };
        }
        let mut count = 0u64;
        let mut i = 0;
        while i + window <= data.len() {
            if shannon_entropy(&data[i..i + window]) > threshold {
                count += window as u64;
                i += window;
            } else {
                i += 1;
            }
        }
        count
    }

    proptest::proptest! {
        #[test]
        fn hit_windows_count_what_the_legacy_counter_counted(
            body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..600),
            low_run in 0usize..80,
        ) {
            let mut body = body;
            body.splice(body.len() / 2..body.len() / 2, std::iter::repeat_n(b'a', low_run));
            let hits = high_entropy_windows(&body, BUDGET_WINDOW, BUDGET_THRESHOLD);
            proptest::prop_assert!(hits.windows(2).all(|p| p[0].end <= p[1].start));
            proptest::prop_assert!(hits.iter().all(|w| w.end <= body.len()));
            proptest::prop_assert_eq!(
                high_entropy_byte_count(&body, BUDGET_WINDOW, BUDGET_THRESHOLD),
                legacy_count(&body, BUDGET_WINDOW, BUDGET_THRESHOLD)
            );
        }
    }
}
