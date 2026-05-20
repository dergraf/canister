//! Declarative DLP transform registry.
//!
//! Single source of truth for every transform attempted by the scan
//! pipeline. Replaces the hardcoded chains that previously lived inside
//! `decode::decode_candidates` and `scanner::scan_text`. Auditors,
//! reviewers, and security engineers can read every transform we run —
//! in cost order — from this file alone.
//!
//! ## Why a registry
//!
//! Pre-refactor, adding a new decoder or encoding-bypass cover meant
//! editing two hot functions and duplicating fragment-aware loops.
//! Cost was implicit — `MAX_TOTAL_LAYERS = 256` was the only knob, so a
//! cheap base64 attempt and a zstd decompression counted equally toward
//! the cap. An attacker could craft inputs that maximised the expensive
//! transforms within the flat budget.
//!
//! After the refactor:
//! - Every transform lives in [`TRANSFORMS`] with an explicit `cost`.
//! - [`crate::decode::decode_layers`] walks `Decode` + `Expensive`
//!   entries in BFS order, deducting cost from a per-call budget.
//! - [`crate::scanner::DlpScanner::scan_text`] walks `Normalize` +
//!   `LastResort` entries flat (one application per layer, with one
//!   composition step for the normalize↔unescape pair).
//!
//! ## Adding a transform
//!
//! 1. Write a `pub(crate) fn apply_*(input: &[u8]) -> Vec<Vec<u8>>` in
//!    this file (or wire up an existing helper).
//! 2. Pick a [`TransformKind`] and a [`Transform::cost`] (see the
//!    cost-tier guidance below).
//! 3. Append to [`TRANSFORMS`] in cost order within its tier.
//!
//! Cost tiers (calibrated against typical attack payloads):
//! - **1** — strip/normalize/percent-decode/whole-buffer base64
//! - **2** — fragment-aware base64/hex passes
//! - **3** — base85 fragment pass (sliding window, b85 alphabet)
//! - **4** — gzip / zlib / zstd decompression
//! - **5** — XOR brute-force over canary prefixes
//!
//! Cheap transforms (`cost ≤ ALWAYS_RUN_COST_THRESHOLD`) always run
//! regardless of remaining budget — they are bounded O(n) and high-recall.
//! Expensive transforms short-circuit once the budget is exhausted; the
//! `tracing::warn!("dlp budget exhausted")` lets operators observe
//! attacker-driven cost in prod.

use crate::decode::{
    fragment_b64_std_pass, fragment_b64_url_pass, fragment_b85_pass, fragment_hex_pass,
    looks_binary, try_base32, try_base64_standard, try_base64_urlsafe, try_decompress_magic,
    try_hex, try_percent_decode, try_utf16_le_to_utf8, xor_brute_for_known_prefixes,
};

/// Bucket a transform falls into. Drives which executor consumes it:
/// `Decode` / `Expensive` flow through the BFS in `decode_layers`,
/// `Normalize` / `LastResort` flow through the flat passes in
/// `scan_text`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformKind {
    /// Cheap, idempotent string normalisations (unicode homoglyphs,
    /// HTML/JSON unescape, token-separator stripping). Applied flat in
    /// `scan_text`; one composition step for `normalize ∘ unescape` is
    /// preserved because real-world payloads stack both.
    Normalize,
    /// Whole-buffer or fragment-aware decoders that materially shift
    /// the bytes (base64, hex, percent, utf16, base32). Run in the
    /// BFS until depth/cost runs out.
    Decode,
    /// Decoders with non-trivial CPU cost (decompression, sliding b85,
    /// XOR brute). Same BFS as `Decode` but the first to be skipped
    /// once budget is exhausted.
    Expensive,
    /// Transforms with a non-zero false-positive risk that we apply
    /// once to the *original* layer only (no composition, no BFS):
    /// reverse, rot13. The detector regexes anchor on specific
    /// prefixes (`AKIA`, `ghp_`, `npm_`), so the FP risk on ordinary
    /// text stays acceptable — but only if we don't compose these.
    LastResort,
}

/// A single registered transform. Pure function over bytes; emits zero
/// or more derived layers. Empty return = "didn't fire on this input"
/// (e.g. base64 of garbage, ascii85 with no b85-specific chars in
/// the wrong size band).
pub struct Transform {
    pub name: &'static str,
    pub cost: u32,
    pub kind: TransformKind,
    pub apply: fn(&[u8]) -> Vec<Vec<u8>>,
}

/// Transforms with `cost <= ALWAYS_RUN_COST_THRESHOLD` are exempt from
/// budget gating. They're cheap enough that running them on every BFS
/// step is fine, and skipping them would degrade recall on perfectly
/// ordinary requests.
pub const ALWAYS_RUN_COST_THRESHOLD: u32 = 2;

/// Default per-`decode_layers` cost budget. Empirically enough to cover
/// every encoding chain the fuzzer has produced (chains of length ≤ 3)
/// while bounding attacker-driven cost.
pub const DEFAULT_COST_BUDGET: u32 = 64;

/// The registry. Ordered cheap → expensive within each kind so the BFS
/// and the flat passes both attempt low-cost / high-recall transforms
/// first. **Reading this array is the audit.**
pub static TRANSFORMS: &[Transform] = &[
    // --- Normalize: applied flat in scan_text ----------------------
    Transform {
        name: "strip_separators",
        cost: 1,
        kind: TransformKind::Normalize,
        apply: apply_strip_separators,
    },
    Transform {
        name: "normalize_unicode",
        cost: 1,
        kind: TransformKind::Normalize,
        apply: apply_normalize_unicode,
    },
    Transform {
        name: "unescape",
        cost: 1,
        kind: TransformKind::Normalize,
        apply: apply_unescape,
    },
    // --- Decode: BFS in decode_layers, never budget-gated ----------
    Transform {
        name: "base64_whole_std",
        cost: 1,
        kind: TransformKind::Decode,
        apply: apply_base64_whole_std,
    },
    Transform {
        name: "base64_whole_url",
        cost: 1,
        kind: TransformKind::Decode,
        apply: apply_base64_whole_url,
    },
    Transform {
        name: "base32_whole",
        cost: 1,
        kind: TransformKind::Decode,
        apply: apply_base32_whole,
    },
    Transform {
        name: "hex_whole",
        cost: 1,
        kind: TransformKind::Decode,
        apply: apply_hex_whole,
    },
    Transform {
        name: "percent_decode",
        cost: 1,
        kind: TransformKind::Decode,
        apply: apply_percent_decode,
    },
    Transform {
        name: "utf16_whole",
        cost: 1,
        kind: TransformKind::Decode,
        apply: apply_utf16_whole,
    },
    Transform {
        name: "b64_fragments_std",
        cost: 2,
        kind: TransformKind::Decode,
        apply: apply_b64_fragments_std,
    },
    Transform {
        name: "b64_fragments_url",
        cost: 2,
        kind: TransformKind::Decode,
        apply: apply_b64_fragments_url,
    },
    Transform {
        name: "hex_fragments",
        cost: 2,
        kind: TransformKind::Decode,
        apply: apply_hex_fragments,
    },
    // --- Expensive: BFS in decode_layers, budget-gated -------------
    Transform {
        name: "b85_fragments",
        cost: 3,
        kind: TransformKind::Expensive,
        apply: apply_b85_fragments,
    },
    Transform {
        name: "decompress_magic",
        cost: 4,
        kind: TransformKind::Expensive,
        apply: apply_decompress_magic,
    },
    Transform {
        name: "xor_known_prefix",
        cost: 5,
        kind: TransformKind::Expensive,
        apply: apply_xor_known_prefix,
    },
    // --- LastResort: applied flat in scan_text, no composition -----
    Transform {
        name: "reverse",
        cost: 1,
        kind: TransformKind::LastResort,
        apply: apply_reverse,
    },
    Transform {
        name: "rot13",
        cost: 2,
        kind: TransformKind::LastResort,
        apply: apply_rot13,
    },
];

/// Iterator over transforms of a given kind, preserving registry order.
pub fn transforms_of(kind: TransformKind) -> impl Iterator<Item = &'static Transform> {
    TRANSFORMS.iter().filter(move |t| t.kind == kind)
}

// =========================================================================
// Normalize adapters
// =========================================================================

fn apply_strip_separators(input: &[u8]) -> Vec<Vec<u8>> {
    // Emit one stripped candidate **per separator character**, plus a
    // strip-all variant. Per-char stripping matters because `-` and
    // `_` are both valid characters inside many credential bodies
    // (`ghp_…`, `sk-ant-…`, `sk_live_…`); stripping them as a set
    // destroys prefix glyphs and a regex anchored on `ghp_` won't fire
    // on `ghpAAAA…`. Stripping one separator at a time keeps the
    // "interleave with a non-token char" obfuscation catchable
    // without touching the legitimate token chars.
    //
    // `+` is included because query strings encode spaces as `+`
    // (form-urlencoded), so interleaved-space exfil in a query
    // parameter arrives as `A+K+I+A+…`. See scanner::scan_text
    // comment block before the refactor for the full rationale.
    const SEPS: &[char] = &['-', ' ', '.', '_', ':', ',', '\t', '+'];
    let Ok(text) = std::str::from_utf8(input) else {
        return Vec::new();
    };
    if text.len() < 16 {
        return Vec::new();
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut seen: Vec<String> = vec![text.to_string()];
    let mut push_if_new = |candidate: String, out: &mut Vec<Vec<u8>>| {
        if candidate.len() >= 16 && !seen.iter().any(|s| s == &candidate) {
            seen.push(candidate.clone());
            out.push(candidate.into_bytes());
        }
    };
    for sep in SEPS {
        let candidate: String = text.chars().filter(|c| c != sep).collect();
        push_if_new(candidate, &mut out);
    }
    let strip_all: String = text.chars().filter(|c| !SEPS.contains(c)).collect();
    push_if_new(strip_all, &mut out);
    out
}

fn apply_normalize_unicode(input: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(input) else {
        return Vec::new();
    };
    let normalized = crate::normalize::normalize(text);
    if normalized == text {
        Vec::new()
    } else {
        vec![normalized.into_bytes()]
    }
}

fn apply_unescape(input: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(input) else {
        return Vec::new();
    };
    let unescaped = crate::unescape::unescape(text);
    if unescaped == text {
        Vec::new()
    } else {
        vec![unescaped.into_bytes()]
    }
}

// =========================================================================
// Decode adapters
// =========================================================================

fn apply_base64_whole_std(input: &[u8]) -> Vec<Vec<u8>> {
    try_base64_standard(input).into_iter().collect()
}

fn apply_base64_whole_url(input: &[u8]) -> Vec<Vec<u8>> {
    try_base64_urlsafe(input).into_iter().collect()
}

fn apply_base32_whole(input: &[u8]) -> Vec<Vec<u8>> {
    try_base32(input).into_iter().collect()
}

fn apply_hex_whole(input: &[u8]) -> Vec<Vec<u8>> {
    try_hex(input).into_iter().collect()
}

fn apply_percent_decode(input: &[u8]) -> Vec<Vec<u8>> {
    try_percent_decode(input).into_iter().collect()
}

fn apply_utf16_whole(input: &[u8]) -> Vec<Vec<u8>> {
    try_utf16_le_to_utf8(input).into_iter().collect()
}

fn apply_b64_fragments_std(input: &[u8]) -> Vec<Vec<u8>> {
    fragment_b64_std_pass(input)
}

fn apply_b64_fragments_url(input: &[u8]) -> Vec<Vec<u8>> {
    fragment_b64_url_pass(input)
}

fn apply_hex_fragments(input: &[u8]) -> Vec<Vec<u8>> {
    fragment_hex_pass(input)
}

// =========================================================================
// Expensive adapters
// =========================================================================

fn apply_b85_fragments(input: &[u8]) -> Vec<Vec<u8>> {
    fragment_b85_pass(input)
}

fn apply_decompress_magic(input: &[u8]) -> Vec<Vec<u8>> {
    try_decompress_magic(input).into_iter().collect()
}

fn apply_xor_known_prefix(input: &[u8]) -> Vec<Vec<u8>> {
    // XOR exfil is almost always on the BINARY layer (hex-decoded
    // payload), so gating on `looks_binary` here would never let it
    // fire on text. The cost of running XOR brute on ordinary text is
    // small (one pass per registered canary prefix), but skipping it
    // when the input is clearly text is a free win.
    if !looks_binary(input) {
        return Vec::new();
    }
    xor_brute_for_known_prefixes(input)
}

// =========================================================================
// LastResort adapters
// =========================================================================

fn apply_reverse(input: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(input) else {
        return Vec::new();
    };
    if text.len() < 16 {
        return Vec::new();
    }
    let reversed: String = text.chars().rev().collect();
    vec![reversed.into_bytes()]
}

fn apply_rot13(input: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(input) else {
        return Vec::new();
    };
    let rot: String = text
        .chars()
        .map(|c| match c {
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            _ => c,
        })
        .collect();
    if rot == text {
        Vec::new()
    } else {
        vec![rot.into_bytes()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_kinds_are_audit_complete() {
        // Tripwire: if a new TransformKind is added but TRANSFORMS
        // forgets to include any entry of that kind, the BFS or the
        // flat pass silently lose coverage. Listing every kind here
        // forces a code review touchpoint.
        let mut saw_normalize = false;
        let mut saw_decode = false;
        let mut saw_expensive = false;
        let mut saw_last_resort = false;
        for tf in TRANSFORMS {
            match tf.kind {
                TransformKind::Normalize => saw_normalize = true,
                TransformKind::Decode => saw_decode = true,
                TransformKind::Expensive => saw_expensive = true,
                TransformKind::LastResort => saw_last_resort = true,
            }
        }
        assert!(saw_normalize && saw_decode && saw_expensive && saw_last_resort);
    }

    #[test]
    fn registry_cost_ordering_within_kinds() {
        // Cheaper-first ordering within each kind is the audit rule —
        // walking the registry top-to-bottom should attempt low-cost
        // high-recall transforms first. A regression here means
        // someone slotted an expensive transform ahead of a cheap one.
        let mut prev_decode_cost = 0;
        let mut prev_expensive_cost = 0;
        for tf in TRANSFORMS {
            match tf.kind {
                TransformKind::Decode => {
                    assert!(
                        tf.cost >= prev_decode_cost,
                        "Decode out of cost order at {}",
                        tf.name
                    );
                    prev_decode_cost = tf.cost;
                }
                TransformKind::Expensive => {
                    assert!(
                        tf.cost >= prev_expensive_cost,
                        "Expensive out of cost order at {}",
                        tf.name
                    );
                    prev_expensive_cost = tf.cost;
                }
                _ => {}
            }
        }
    }

    #[test]
    fn rot13_self_inverse() {
        let input = b"AKIAIOSFODNN7EXAMPLE";
        let once = apply_rot13(input);
        assert_eq!(once.len(), 1);
        let twice = apply_rot13(&once[0]);
        assert_eq!(twice.len(), 1);
        assert_eq!(twice[0], input);
    }

    #[test]
    fn reverse_below_threshold_returns_empty() {
        // Reverse on short strings is high FP, so the gate is part of
        // the transform's apply contract — the executor doesn't need
        // to know.
        assert!(apply_reverse(b"short").is_empty());
        assert_eq!(apply_reverse(b"AKIAIOSFODNN7EXAMPLE").len(), 1);
    }

    #[test]
    fn strip_separators_skips_unmodified() {
        let plain = b"AKIAIOSFODNN7EXAMPLE";
        assert!(
            apply_strip_separators(plain).is_empty(),
            "no-op transforms must return empty"
        );
    }
}
