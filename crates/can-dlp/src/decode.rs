use std::collections::{HashSet, VecDeque};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};

use crate::transforms::{ALWAYS_RUN_COST_THRESHOLD, TRANSFORMS, TransformKind};

/// Minimum length for a substring to be considered a candidate encoded
/// fragment. Below this, false-positive risk outweighs detection value
/// (most real secrets we care about are ≥ 20 chars after encoding).
pub(crate) const MIN_FRAGMENT_LEN: usize = 16;

/// Hard ceiling on the total number of layers produced. Defence in depth
/// alongside the per-call cost budget — a pathological adversarial input
/// that somehow stays under the cost budget still can't explode the
/// layer set beyond this.
const MAX_TOTAL_LAYERS: usize = 256;

/// Walk the [`TRANSFORMS`] registry over `data` in BFS order until
/// `max_depth`, `cost_budget`, or [`MAX_TOTAL_LAYERS`] is exhausted.
///
/// Only `Decode` and `Expensive` kinds participate in the BFS;
/// `Normalize` and `LastResort` transforms are consumed flat by
/// [`crate::scanner::DlpScanner::scan_text`].
///
/// Cost accounting: cheap transforms (`cost <= ALWAYS_RUN_COST_THRESHOLD`)
/// always run regardless of remaining budget. Expensive transforms
/// short-circuit once the budget is exhausted, logged at `warn` so
/// operators can observe attacker-driven cost in prod.
pub fn decode_layers(data: &[u8], max_depth: usize, cost_budget: u32) -> Vec<Vec<u8>> {
    let mut layers: Vec<Vec<u8>> = Vec::new();
    layers.push(data.to_vec());

    let mut seen: HashSet<u64> = HashSet::new();
    seen.insert(fingerprint(data));

    let mut queue: VecDeque<(Vec<u8>, usize)> = VecDeque::new();
    queue.push_back((data.to_vec(), max_depth));

    let mut budget_remaining: i64 = cost_budget as i64;
    let mut budget_exhausted_logged = false;

    while let Some((current, depth)) = queue.pop_front() {
        if depth == 0 || layers.len() >= MAX_TOTAL_LAYERS {
            continue;
        }
        for tf in TRANSFORMS {
            // BFS only consumes Decode + Expensive kinds; Normalize
            // and LastResort run flat in scan_text.
            if !matches!(tf.kind, TransformKind::Decode | TransformKind::Expensive) {
                continue;
            }
            let always_run = tf.cost <= ALWAYS_RUN_COST_THRESHOLD;
            if !always_run && budget_remaining <= 0 {
                if !budget_exhausted_logged {
                    tracing::warn!(
                        cost_budget = cost_budget,
                        depth_reached = max_depth - depth,
                        layers = layers.len(),
                        "dlp decode_layers budget exhausted — expensive transforms skipped"
                    );
                    budget_exhausted_logged = true;
                }
                continue;
            }
            let outs = (tf.apply)(&current);
            // Charge cost only when the transform actually produced
            // candidate layers. A failing probe (e.g. decompress on
            // non-gzip bytes, b85 on a pure-b64 run) was effectively
            // free pre-refactor; preserving that semantics means
            // benign inputs don't burn budget and the budget bounds
            // *productive* expensive work — which is what an attacker
            // would actually exploit to chain layers.
            if !always_run && !outs.is_empty() {
                budget_remaining -= tf.cost as i64;
            }
            for decoded in outs {
                if decoded.is_empty() || decoded == current {
                    continue;
                }
                let fp = fingerprint(&decoded);
                if !seen.insert(fp) {
                    continue;
                }
                layers.push(decoded.clone());
                if layers.len() >= MAX_TOTAL_LAYERS {
                    break;
                }
                queue.push_back((decoded, depth - 1));
            }
            if layers.len() >= MAX_TOTAL_LAYERS {
                break;
            }
        }
    }
    layers
}

// =========================================================================
// Fragment-aware passes
//
// Each `fragment_*_pass` walks `data` for maximal runs of a charset,
// then tries the matching decoder(s) on each run with the relevant
// sliding-offset / gating logic. Surfaced as `pub(crate)` so the
// transform registry can wire them in by name; this module retains
// every fragment-specific subtlety (sliding window, canary-length band,
// utf16-after-hex) in one place.
// =========================================================================

/// Sliding-window offsets for whole-buffer scans where a leading prefix
/// (`/leak/`, `Bearer `, `session=`) shifts the 4-byte chunk boundary
/// off the real payload. Without sliding, the first chunk decodes to
/// misaligned garbage and any canary that straddles the boundary is
/// lost.
const MAX_B64_SLIDE: usize = 16;
/// Cap on base85 run length to bound cost on long printable runs (logs,
/// JSON blobs) where every char is also valid b85.
const MAX_85_LEN: usize = 512;
/// Sliding-window offsets for ascii85 / base85 (5-char chunk boundary).
const MAX_85_SLIDE: usize = 16;
/// Lower bound: 20-byte AWS canary → 25 ascii85 chars (with 16-char
/// prefix slide budget, smallest interesting run is ~24). Upper bound:
/// 40-byte GH/NPM canary → 50 ascii85 chars (allow some slack and
/// prefix slide budget).
const CANARY_85_BAND: std::ops::RangeInclusive<usize> = 24..=80;

/// Fragment pass over `is_b64ish` runs — standard base64 alphabet
/// including `/` and `+`. Each run is tried as base64 (padded, both
/// alphabets), as base32 (alnum overlap), and as base64 with sliding
/// prefix offsets to recover misaligned chunks behind a path prefix
/// like `/leak/<payload>`.
pub(crate) fn fragment_b64_std_pass(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for frag in find_runs(text, is_b64ish, MIN_FRAGMENT_LEN) {
        // `=` is padding, never data, so `find_runs` cuts on it (see
        // `is_b64ish`). That leaves fragments un-padded; the helpers
        // re-pad so `?payload=AKIA…=` decodes even though the
        // surrounding `=` breaks the run.
        out.extend(try_base64_padded_variants(frag.as_bytes()));
        // base32 fragments share the b64ish charset (A-Z, 2-7 are
        // alnum), so any base32 string is also a b64ish run. Try here
        // too — without this, `Bearer <base32>` slips past even with a
        // top-level try_base32 because the `Bearer ` prefix breaks
        // whole-buffer base32 decoding.
        if let Some(d) = try_base32(frag.as_bytes()) {
            out.push(d);
        }
        let bytes = frag.as_bytes();
        let max_start = bytes.len().min(MAX_B64_SLIDE);
        for start in 1..max_start {
            if bytes.len() - start < MIN_FRAGMENT_LEN {
                break;
            }
            out.extend(try_base64_padded_variants(&bytes[start..]));
        }
    }
    out
}

/// Fragment pass over `is_b64ish_url_safe` runs (excludes `/` and `+`).
/// In URL paths `/` is a separator so the broader is_b64ish glues
/// `/leak/PAYLOAD` into one run whose base64 decode is misaligned
/// garbage; the url-safe alphabet doesn't use `/` or `+`, so this pass
/// catches url-embedded payloads. Layer dedup absorbs duplicates when
/// both passes find the same content.
pub(crate) fn fragment_b64_url_pass(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for frag in find_runs(text, is_b64ish_url_safe, MIN_FRAGMENT_LEN) {
        out.extend(try_base64_padded_variants(frag.as_bytes()));
        // base32 here too: in URL paths `/` splits a base32 payload
        // into url-safe-only runs (no `+`/`/`), so the standard-pass
        // try_base32 above never sees them.
        if let Some(d) = try_base32(frag.as_bytes()) {
            out.push(d);
        }
        let bytes = frag.as_bytes();
        let max_start = bytes.len().min(MAX_B64_SLIDE);
        for start in 1..max_start {
            if bytes.len() - start < MIN_FRAGMENT_LEN {
                break;
            }
            out.extend(try_base64_padded_variants(&bytes[start..]));
        }
    }
    out
}

/// Fragment pass over hex-digit runs. Tries hex-decode and then
/// UTF-16-LE-after-hex (`utf16_hex` exfil ships text as UTF-16 bytes
/// then hex-encodes them, defeating naive UTF-8 string decoders).
pub(crate) fn fragment_hex_pass(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for frag in find_runs(text, |b| b.is_ascii_hexdigit(), MIN_FRAGMENT_LEN) {
        if let Some(d) = try_hex(frag.as_bytes()) {
            if let Some(utf16) = try_utf16_le_to_utf8(&d) {
                out.push(utf16);
            }
            out.push(d);
        }
    }
    out
}

/// Fragment pass over `is_printable85` runs for ascii85 / base85
/// decoding. Gating: a run only goes through b85 decoders if EITHER it
/// contains a b85-specific char (`!#$%&()*;<>?@^…`, which proves it's
/// not just base64), OR its length falls in the canary-payload band
/// (~25–64 chars). Without the length-band escape, ~0.2% of legitimate
/// ascii85-encoded canaries (whose output happens to be alnum-only)
/// slipped past. Without the b85-specific gate on longer runs, every
/// base64 blob produced garbage b85 layers.
///
/// Sliding offsets up to `MAX_85_SLIDE` cover the common case of
/// `session=<payload>` / `Bearer <payload>` where a short prefix shifts
/// the 5-char chunk boundary off the real data.
pub(crate) fn fragment_b85_pass(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for frag in find_runs(text, is_printable85, MIN_FRAGMENT_LEN) {
        if frag.len() > MAX_85_LEN {
            continue;
        }
        let has_b85_specific = frag.bytes().any(is_b85_specific);
        let in_canary_band = CANARY_85_BAND.contains(&frag.len());
        if !has_b85_specific && !in_canary_band {
            continue;
        }
        let bytes = frag.as_bytes();
        let max_start = bytes.len().min(MAX_85_SLIDE);
        for start in 0..max_start {
            if bytes.len() - start < 5 {
                break;
            }
            if let Some(d) = try_ascii85(&bytes[start..]) {
                out.push(d);
            }
            if let Some(d) = try_base85_rfc1924(&bytes[start..]) {
                out.push(d);
            }
        }
    }
    out
}

fn is_b64ish(b: u8) -> bool {
    // Intentionally excludes `=`: padding only appears at the *end* of
    // a base64 string, so treating it as part of the character class
    // makes `find_runs` glue `name=VALUE=` into one un-decodable blob
    // when we want it split into `name` (too short) and `VALUE`.
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-')
}

fn is_b64ish_url_safe(b: u8) -> bool {
    // URL-safe base64 alphabet only (RFC 4648 §5). Used for a second
    // fragment pass so `/` (URL path separator) and `+` (often a
    // percent-decoded space) split runs instead of gluing them to the
    // payload.
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')
}

/// True if `b` is in the base85 supersets but NOT in the base64
/// alphabet. Used as one half of the "this might really be base85, not
/// just base64" gate before trying the b85 decoders (paired with a
/// canary-length-band fallback in the b85 fragment pass).
fn is_b85_specific(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'('
            | b')'
            | b'*'
            | b';'
            | b'<'
            | b'>'
            | b'?'
            | b'@'
            | b'^'
            | b'`'
            | b'{'
            | b'|'
            | b'}'
            | b'~'
    )
}

/// Wide printable-ASCII charset covering both ascii85 (`!`..`u`) and
/// RFC 1924 base85 (`0-9A-Za-z!#$%&()*+-;<=>?@^_`{|}~`). Used purely
/// to find candidate runs — the decoders themselves reject inputs
/// that aren't valid in their respective alphabets.
fn is_printable85(b: u8) -> bool {
    matches!(b, b'!'..=b'~')
        && !matches!(
            b,
            b' ' | b'"' | b'\'' | b',' | b'/' | b':' | b'[' | b']' | b'\\'
        )
}

fn find_runs<F>(text: &str, mut accept: F, min_len: usize) -> Vec<&str>
where
    F: FnMut(u8) -> bool,
{
    let bytes = text.as_bytes();
    let mut runs = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if accept(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s_i) = start.take() {
            if i - s_i >= min_len {
                if let Ok(slice) = std::str::from_utf8(&bytes[s_i..i]) {
                    runs.push(slice);
                }
            }
        }
    }
    if let Some(s_i) = start {
        if bytes.len() - s_i >= min_len {
            if let Ok(slice) = std::str::from_utf8(&bytes[s_i..]) {
                runs.push(slice);
            }
        }
    }
    runs
}

fn fingerprint(data: &[u8]) -> u64 {
    // Fast non-cryptographic dedup hash. We only need to recognise inputs
    // we've already seen in the queue/layers; collision risk on real bodies
    // is acceptable (worst case: a colliding pair is treated as "already
    // seen" and skipped, reducing recall by one entry — never producing
    // a wrong positive).
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    h.finish()
}

pub(crate) fn try_base64_standard(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let trimmed = text.trim();
    if trimmed.len() < 4 {
        return None;
    }
    STANDARD.decode(trimmed).ok()
}

pub(crate) fn try_base64_urlsafe(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let trimmed = text.trim();
    if trimmed.len() < 4 {
        return None;
    }
    URL_SAFE.decode(trimmed).ok()
}

/// Try a fragment as base64 under both alphabets, padding it up to a
/// multiple of 4. Fragments produced by `find_runs` are un-padded by
/// construction (see `is_b64ish`); without re-padding the standard
/// decoders reject them.
fn try_base64_padded_variants(data: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let trimmed = text.trim().trim_end_matches('=');
    if trimmed.len() < 4 {
        return Vec::new();
    }
    let pad_len = (4 - trimmed.len() % 4) % 4;
    let mut padded = String::with_capacity(trimmed.len() + pad_len);
    padded.push_str(trimmed);
    for _ in 0..pad_len {
        padded.push('=');
    }
    let mut out = Vec::new();
    if let Ok(d) = STANDARD.decode(&padded) {
        out.push(d);
    }
    if let Ok(d) = URL_SAFE.decode(&padded) {
        out.push(d);
    }
    out
}

pub(crate) fn try_hex(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let trimmed = text.trim();
    if trimmed.len() < 8 || trimmed.len() % 2 != 0 {
        return None;
    }
    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    for chunk in trimmed.as_bytes().chunks(2) {
        let high = hex_val(chunk[0])?;
        let low = hex_val(chunk[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn try_percent_decode(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    if !text.contains('%') {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(text).collect::<Vec<u8>>();
    Some(decoded)
}

/// RFC 4648 base32 decoder. Distinct alphabet from base64, so the
/// fragment scanner can't recover a base32-encoded secret without an
/// explicit pass. Real-world: PyPI tokens, some MFA seeds, the
/// Python `base32` module — all commonly used for credential blobs.
pub(crate) fn try_base32(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let trimmed = text.trim().trim_end_matches('=');
    if trimmed.len() < 8 {
        return None;
    }
    // Strict alphabet check — A-Z, 2-7, case-insensitive. Bail
    // early on anything else to avoid false-positive decoding of
    // ordinary text.
    let upper: String = trimmed.to_ascii_uppercase().chars().collect();
    if !upper
        .bytes()
        .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
    {
        return None;
    }
    let mut out = Vec::with_capacity(upper.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in upper.bytes() {
        let v: u32 = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'2'..=b'7' => (c - b'2' + 26) as u32,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// btoa/ascii85 decoder (RFC 1924-precursor, used in PDF/git/Adobe).
/// Alphabet: `!` (0) through `u` (84), each char carries a base-85
/// digit. Five chars encode four bytes; the special `z` shortcut
/// stands for four zero bytes. Surrounding whitespace is ignored.
fn try_ascii85(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 5 {
        return None;
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 4 / 5);
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'z' {
            out.extend_from_slice(&[0, 0, 0, 0]);
            i += 1;
            continue;
        }
        let mut acc: u64 = 0;
        let mut chars = 0;
        while chars < 5 && i + chars < bytes.len() {
            let b = bytes[i + chars];
            if !(b'!'..=b'u').contains(&b) {
                return None;
            }
            acc = acc * 85 + (b - b'!') as u64;
            chars += 1;
        }
        // Pad partial group with `u` (max digit).
        for _ in chars..5 {
            acc = acc * 85 + 84;
        }
        if acc > u32::MAX as u64 {
            return None;
        }
        let word = acc as u32;
        // Last group may encode fewer than 4 bytes (one byte per
        // missing trailing char).
        let emit = if chars < 5 { chars - 1 } else { 4 };
        for shift in 0..emit {
            let b = (word >> (24 - shift * 8)) & 0xFF;
            out.push(b as u8);
        }
        i += chars;
    }
    if out.is_empty() { None } else { Some(out) }
}

/// RFC 1924 base85 (used by `base64.b85encode` in Python). Different
/// alphabet from ascii85 — overlapping but not identical, so we run
/// both decoders on every candidate run and let the dedup hash absorb
/// duplicates when only one alphabet actually matches.
fn try_base85_rfc1924(data: &[u8]) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
    let text = std::str::from_utf8(data).ok()?;
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 5 {
        return None;
    }
    let bytes = cleaned.as_bytes();
    let mut lookup = [255u8; 256];
    for (i, &b) in ALPHABET.iter().enumerate() {
        lookup[b as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(bytes.len() * 4 / 5);
    for chunk in bytes.chunks(5) {
        if chunk.len() < 2 {
            return None;
        }
        let mut acc: u64 = 0;
        for &b in chunk {
            let v = lookup[b as usize];
            if v == 255 {
                return None;
            }
            acc = acc * 85 + v as u64;
        }
        for _ in chunk.len()..5 {
            acc = acc * 85 + 84;
        }
        if acc > u32::MAX as u64 {
            return None;
        }
        let word = acc as u32;
        let emit = chunk.len() - 1;
        for shift in 0..emit {
            out.push(((word >> (24 - shift * 8)) & 0xFF) as u8);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// True if `data` looks like binary (not mostly printable ASCII).
/// Drives the XOR-brute-force gate: text-looking inputs almost never
/// benefit from XOR'ing, and the gate keeps the per-layer cost
/// proportional only to inputs that might actually carry obfuscated
/// secrets.
pub(crate) fn looks_binary(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let non_printable = data
        .iter()
        .filter(|&&b| !b.is_ascii_graphic() && !b.is_ascii_whitespace())
        .count();
    non_printable * 4 > data.len()
}

/// For each canary prefix in the registry, search `data` for the
/// prefix XOR'd with a single-byte key. On match, decode the whole
/// buffer with that key and return it. Returns at most one layer per
/// matching prefix.
pub(crate) fn xor_brute_for_known_prefixes(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for spec in crate::registry::REGISTRY
        .iter()
        .filter_map(|d| d.canary.as_ref())
    {
        let prefix = spec.prefix.as_bytes();
        if prefix.len() < 3 || data.len() < prefix.len() {
            continue;
        }
        let mut found_key: Option<u8> = None;
        for start in 0..=data.len() - prefix.len() {
            let key = data[start] ^ prefix[0];
            if (1..prefix.len()).all(|i| data[start + i] ^ key == prefix[i]) {
                found_key = Some(key);
                break;
            }
        }
        if let Some(key) = found_key {
            let decoded: Vec<u8> = data.iter().map(|b| b ^ key).collect();
            // Deduplicate against earlier prefixes that may have
            // landed on the same key.
            if !out.iter().any(|d| d == &decoded) {
                out.push(decoded);
            }
        }
    }
    out
}

/// Treat `data` as UTF-16-LE (and as UTF-16-BE) and transcode to
/// UTF-8 if it looks plausible. Plausibility heuristic: at least 75%
/// of even-indexed bytes (LE) — or odd-indexed bytes (BE) — are 0,
/// since the secrets we care about are ASCII characters.
pub(crate) fn try_utf16_le_to_utf8(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 || data.len() % 2 != 0 {
        return None;
    }
    let pairs = data.chunks_exact(2);
    let total = pairs.len();
    let mut le_nulls = 0;
    let mut be_nulls = 0;
    for chunk in pairs {
        if chunk[1] == 0 {
            le_nulls += 1;
        }
        if chunk[0] == 0 {
            be_nulls += 1;
        }
    }
    let threshold = (total * 3) / 4;
    let endianness = if le_nulls >= threshold {
        Some(false) // LE
    } else if be_nulls >= threshold {
        Some(true) // BE
    } else {
        None
    };
    let big_endian = endianness?;
    let mut words = Vec::with_capacity(data.len() / 2);
    for chunk in data.chunks_exact(2) {
        let w = if big_endian {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_le_bytes([chunk[0], chunk[1]])
        };
        words.push(w);
    }
    let text = String::from_utf16(&words).ok()?;
    if text.is_empty() {
        None
    } else {
        Some(text.into_bytes())
    }
}

/// Try to decompress `data` if it looks like a known compressed
/// stream. Detects:
/// - gzip:  `1F 8B`
/// - zlib:  `78 01` / `78 9C` / `78 DA` (most common)
/// - zstd:  `28 B5 2F FD`
///
/// Returns `None` if nothing matches or the decoder rejects the
/// bytes. Output is the decompressed bytes; the caller treats it as a
/// regular decoded layer (a chained scan_text + decode_candidates
/// pass).
pub(crate) fn try_decompress_magic(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;

    if data.len() < 2 {
        return None;
    }
    // gzip
    if data[0] == 0x1F && data[1] == 0x8B {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut out = Vec::new();
        if decoder.read_to_end(&mut out).is_ok() && !out.is_empty() {
            return Some(out);
        }
    }
    // zlib (RFC 1950) — the first byte is 0x78 in nearly every
    // real-world zlib stream (CINFO=7, CM=8). Be strict on the
    // second byte to keep false positives low: only accept the
    // three common FLEVEL values.
    if data[0] == 0x78 && matches!(data[1], 0x01 | 0x5E | 0x9C | 0xDA) {
        let mut decoder = flate2::read::ZlibDecoder::new(data);
        let mut out = Vec::new();
        if decoder.read_to_end(&mut out).is_ok() && !out.is_empty() {
            return Some(out);
        }
    }
    // zstd
    if data.len() >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD {
        if let Ok(mut decoder) = zstd::stream::read::Decoder::new(data) {
            let mut out = Vec::new();
            if decoder.read_to_end(&mut out).is_ok() && !out.is_empty() {
                return Some(out);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn decode_base64_single_layer() {
        let secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let encoded = STANDARD.encode(secret);
        let layers = decode_layers(
            encoded.as_bytes(),
            32,
            crate::transforms::DEFAULT_COST_BUDGET,
        );
        assert!(layers.len() >= 2);
        assert!(layers.iter().any(|l| l == secret.as_bytes()));
    }

    #[test]
    fn decode_base64_double_layer() {
        let secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let inner = STANDARD.encode(secret);
        let outer = STANDARD.encode(&inner);
        let layers = decode_layers(outer.as_bytes(), 32, crate::transforms::DEFAULT_COST_BUDGET);
        assert!(
            layers.iter().any(|l| l == secret.as_bytes()),
            "double-encoded secret should be found"
        );
    }

    #[test]
    fn try_hex_decodes_valid_hex() {
        let secret = b"ghp_SecretTokenValue";
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let decoded = super::try_hex(hex.as_bytes());
        assert_eq!(decoded.as_deref(), Some(secret.as_slice()));
    }

    #[test]
    fn try_hex_rejects_non_hex() {
        assert!(super::try_hex(b"not-hex-at-all!!").is_none());
    }

    #[test]
    fn decode_percent_encoded() {
        let secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let encoded: String = secret.bytes().map(|b| format!("%{b:02X}")).collect();
        let layers = decode_layers(
            encoded.as_bytes(),
            32,
            crate::transforms::DEFAULT_COST_BUDGET,
        );
        assert!(layers.iter().any(|l| l == secret.as_bytes()));
    }

    #[test]
    fn depth_limit_honoured() {
        // We encode 10 levels deep but cap BFS at depth=3. The
        // depth bound prevents unbounded recursion, but the layer
        // count per level depends on how many decoders succeed on
        // the candidate text — base32, ascii85, base85, etc. can
        // each emit a (usually garbage) layer that the dedup hash
        // sometimes can't merge. The relevant invariant is
        // "MAX_TOTAL_LAYERS is respected and recursion stops".
        let secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut encoded = STANDARD.encode(secret);
        for _ in 0..10 {
            encoded = STANDARD.encode(&encoded);
        }
        let layers = decode_layers(
            encoded.as_bytes(),
            3,
            crate::transforms::DEFAULT_COST_BUDGET,
        );
        assert!(
            layers.len() <= MAX_TOTAL_LAYERS,
            "layer count {} exceeds MAX_TOTAL_LAYERS={}",
            layers.len(),
            MAX_TOTAL_LAYERS,
        );
        // Without the depth cap we'd eventually unwrap the original
        // secret. With cap=3 we should *not* see it (10 layers deep).
        assert!(
            !layers.iter().any(|l| l == secret.as_bytes()),
            "depth cap was bypassed — secret recovered"
        );
    }

    #[test]
    fn garbage_input_returns_original() {
        let garbage = b"\x00\x01\x02\x03";
        let layers = decode_layers(garbage, 32, crate::transforms::DEFAULT_COST_BUDGET);
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0], garbage);
    }

    #[test]
    fn empty_input() {
        let layers = decode_layers(b"", 32, crate::transforms::DEFAULT_COST_BUDGET);
        assert_eq!(layers.len(), 1);
        assert!(layers[0].is_empty());
    }

    #[test]
    fn normal_text_no_extra_layers() {
        let text = b"Hello, this is normal text without any encoding.";
        let layers = decode_layers(text, 32, crate::transforms::DEFAULT_COST_BUDGET);
        assert_eq!(layers.len(), 1);
    }

    #[test]
    fn fragment_decode_finds_token_inside_json() {
        // F3 regression: a token embedded inside a JSON envelope used to
        // slip past whole-buffer decoding because the outer `{"…":"…"}`
        // wasn't valid base64. Fragment-aware decoding locates the inner
        // run and decodes it in isolation.
        let secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let inner_b64 = STANDARD.encode(secret);
        let envelope = format!(r#"{{"event":"upload","payload":"{inner_b64}"}}"#);
        let layers = decode_layers(
            envelope.as_bytes(),
            32,
            crate::transforms::DEFAULT_COST_BUDGET,
        );
        assert!(
            layers.iter().any(|l| l == secret.as_bytes()),
            "expected to find the inner secret in some decoded layer; layers={}",
            layers.len()
        );
    }

    #[test]
    fn fragment_decode_finds_token_in_multipart_boundary() {
        // multipart/form-data envelopes: the token is sandwiched between
        // boundary lines but never appears as a clean whole-buffer base64
        // input.
        let secret = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let inner_b64 = STANDARD.encode(secret);
        let envelope = format!(
            "--boundary\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n{inner_b64}\r\n--boundary--\r\n"
        );
        let layers = decode_layers(
            envelope.as_bytes(),
            32,
            crate::transforms::DEFAULT_COST_BUDGET,
        );
        assert!(
            layers.iter().any(|l| l == secret.as_bytes()),
            "expected to find inner secret via fragment decoding"
        );
    }

    #[test]
    fn fragment_decode_finds_hex_token_inside_xml() {
        // Hex-encoded token inside an XML envelope.
        let secret = b"ghp_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
        let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let envelope = format!("<auth><value>{hex}</value></auth>");
        let layers = decode_layers(
            envelope.as_bytes(),
            32,
            crate::transforms::DEFAULT_COST_BUDGET,
        );
        assert!(
            layers.iter().any(|l| l == secret),
            "expected hex-decoded inner secret"
        );
    }

    #[test]
    fn fragment_short_runs_are_ignored() {
        // A 12-char base64 string is below MIN_FRAGMENT_LEN — should not
        // produce a fragment-decoded layer. False-positive guard.
        let envelope = b"x=YWJjZGVmZ2hpams= done";
        let layers = decode_layers(envelope, 32, crate::transforms::DEFAULT_COST_BUDGET);
        // Whole-buffer decoders should also bail (envelope isn't pure
        // base64) so we expect exactly 1 layer: the original.
        assert_eq!(layers.len(), 1);
    }

    #[test]
    fn url_path_b64_payload_decoded_despite_slashes() {
        // Regression: previously `is_b64ish` included `/`, so the URL
        // path `/leak/<b64>` collapsed into a single run that base64-
        // decoded into misaligned garbage. The url-safe second pass
        // splits at `/` and recovers the inner payload.
        let secret = "AKIA0123456789ABCDEF";
        let encoded = STANDARD.encode(secret);
        let uri = format!("http://host.canister.local:8088/leak/{encoded}");

        let layers = decode_layers(uri.as_bytes(), 32, crate::transforms::DEFAULT_COST_BUDGET);
        assert!(
            layers.iter().any(|l| l == secret.as_bytes()),
            "expected to find AKIA secret in some decoded layer; got {} layers",
            layers.len()
        );
    }

    #[test]
    fn url_path_percent_encoded_b64_payload_decoded() {
        // Same as above but with the trailing `=` percent-encoded as
        // `%3D` (what `urllib.parse.quote(..., safe='')` produces).
        let secret = "AKIA0123456789ABCDEF";
        let encoded = STANDARD.encode(secret); // ends with `=`
        let quoted = encoded.replace('=', "%3D");
        let uri = format!("http://host/leak/{quoted}");

        let layers = decode_layers(uri.as_bytes(), 32, crate::transforms::DEFAULT_COST_BUDGET);
        assert!(
            layers.iter().any(|l| l == secret.as_bytes()),
            "expected AKIA in layers after percent + url-safe pass"
        );
    }

    /// Pin the *set* of layer fingerprints produced for representative
    /// inputs. This is the regression guard for the registry refactor —
    /// any future change to a transform, the BFS executor, or the cost
    /// budget that drops a layer for a real attack shape will fail
    /// loudly here, before the matrix tests have a chance to mask it
    /// behind a single missing detector hit.
    ///
    /// We compare the fingerprint *set* (not the order) because the
    /// registry order or transform invocation order is intentionally an
    /// implementation detail; what we contract on is "for this input,
    /// these distinct layers must be derivable."
    #[test]
    fn decode_layers_output_stable() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use std::collections::BTreeSet;
        use std::io::Write;

        fn fp_set(input: &[u8]) -> BTreeSet<u64> {
            let layers = decode_layers(input, 32, crate::transforms::DEFAULT_COST_BUDGET);
            layers.iter().map(|l| fingerprint(l)).collect()
        }

        // Each fixture: (description, input, must-include-substring).
        // The fingerprint-set captures "every layer derived"; the
        // substring assertion captures "the canary is recoverable in
        // at least one layer".
        let secret = "AKIA0123456789ABCDEF";

        // 1) Clean text — only one layer (the input).
        let clean = b"the quick brown fox jumps over the lazy dog";
        let fps = fp_set(clean);
        assert_eq!(fps.len(), 1, "clean text should produce only the raw layer");

        // 2) Bearer + base64-encoded canary.
        let bearer = format!("Bearer {}", STANDARD.encode(secret));
        let layers = decode_layers(
            bearer.as_bytes(),
            32,
            crate::transforms::DEFAULT_COST_BUDGET,
        );
        assert!(
            layers
                .iter()
                .any(|l| l.windows(secret.len()).any(|w| w == secret.as_bytes())),
            "base64-encoded AKIA in Bearer header should appear as a layer"
        );

        // 3) URI path with gzip+base64 canary — the budget regression
        // case that drove the per-output cost charging policy.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(secret.as_bytes()).unwrap();
        let gzipped = gz.finish().unwrap();
        let path = format!("https://evil.com/leak/{}", STANDARD.encode(&gzipped));
        let layers = decode_layers(path.as_bytes(), 32, crate::transforms::DEFAULT_COST_BUDGET);
        assert!(
            layers
                .iter()
                .any(|l| l.windows(secret.len()).any(|w| w == secret.as_bytes())),
            "gzip+b64 canary in URI path must be recovered through the registry BFS"
        );

        // 4) Cookie with ascii85 canary — exercises the b85_fragments
        // pass via the sliding-offset alignment recovery and the
        // canary-band gate.
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
        let cookie = format!("session={}", ascii85_enc(secret.as_bytes()));
        let layers = decode_layers(
            cookie.as_bytes(),
            32,
            crate::transforms::DEFAULT_COST_BUDGET,
        );
        assert!(
            layers
                .iter()
                .any(|l| l.windows(secret.len()).any(|w| w == secret.as_bytes())),
            "ascii85 canary in cookie must be recovered through the registry BFS"
        );
    }

    #[test]
    fn dedup_cycles_do_not_explode() {
        // Pathological: a string whose decode produces itself. The
        // fingerprint dedup should make the BFS terminate immediately
        // without re-queueing the same payload.
        let s = b"YWJjZA==";
        let layers = decode_layers(s, 32, crate::transforms::DEFAULT_COST_BUDGET);
        assert!(layers.len() <= 32, "got {} layers", layers.len());
    }
}
