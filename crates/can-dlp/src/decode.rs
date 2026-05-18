use std::collections::{HashSet, VecDeque};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};

/// Minimum length for a substring to be considered a candidate encoded
/// fragment. Below this, false-positive risk outweighs detection value
/// (most real secrets we care about are ≥ 20 chars after encoding).
const MIN_FRAGMENT_LEN: usize = 16;

/// Hard cap on the total number of layers produced. Without this, a
/// pathological adversarial input could explode (fragment decode → many
/// substring matches → each spawns more layers). 256 is comfortably above
/// any legitimate body we've measured.
const MAX_TOTAL_LAYERS: usize = 256;

pub fn decode_layers(data: &[u8], max_depth: usize) -> Vec<Vec<u8>> {
    let mut layers: Vec<Vec<u8>> = Vec::new();
    layers.push(data.to_vec());

    let mut seen: HashSet<u64> = HashSet::new();
    seen.insert(fingerprint(data));

    let mut queue: VecDeque<(Vec<u8>, usize)> = VecDeque::new();
    queue.push_back((data.to_vec(), max_depth));

    while let Some((current, depth)) = queue.pop_front() {
        if depth == 0 || layers.len() >= MAX_TOTAL_LAYERS {
            continue;
        }
        for decoded in decode_candidates(&current) {
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
    }
    layers
}

/// All decode candidates for `data`: whole-buffer decoders first, then
/// fragment-aware substring decodes.
///
/// Fragment-aware decoding is the F3 fix: a base64 token embedded inside a
/// larger JSON/XML/multipart envelope used to slip past the scanner because
/// `try_base64_standard(whole_buffer)` returned None on the outer bytes.
/// Now we additionally locate maximal runs of base64-/hex-charset bytes
/// (≥ `MIN_FRAGMENT_LEN`) and decode each in isolation.
fn decode_candidates(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();

    if let Some(d) = try_base64_standard(data) {
        out.push(d);
    }
    if let Some(d) = try_base64_urlsafe(data) {
        out.push(d);
    }
    if let Some(d) = try_hex(data) {
        out.push(d);
    }
    if let Some(d) = try_percent_decode(data) {
        out.push(d);
    }

    if let Ok(text) = std::str::from_utf8(data) {
        for frag in find_runs(text, is_b64ish, MIN_FRAGMENT_LEN) {
            if let Some(d) = try_base64_standard(frag.as_bytes()) {
                out.push(d);
            }
            if let Some(d) = try_base64_urlsafe(frag.as_bytes()) {
                out.push(d);
            }
        }
        for frag in find_runs(text, |b| b.is_ascii_hexdigit(), MIN_FRAGMENT_LEN) {
            if let Some(d) = try_hex(frag.as_bytes()) {
                out.push(d);
            }
        }
    }

    out
}

fn is_b64ish(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'_' | b'-' | b'=')
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

fn try_base64_standard(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let trimmed = text.trim();
    if trimmed.len() < 4 {
        return None;
    }
    STANDARD.decode(trimmed).ok()
}

fn try_base64_urlsafe(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let trimmed = text.trim();
    if trimmed.len() < 4 {
        return None;
    }
    URL_SAFE.decode(trimmed).ok()
}

fn try_hex(data: &[u8]) -> Option<Vec<u8>> {
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

fn try_percent_decode(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    if !text.contains('%') {
        return None;
    }
    let decoded = percent_encoding::percent_decode_str(text).collect::<Vec<u8>>();
    Some(decoded)
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
        let layers = decode_layers(encoded.as_bytes(), 32);
        assert!(layers.len() >= 2);
        assert!(layers.iter().any(|l| l == secret.as_bytes()));
    }

    #[test]
    fn decode_base64_double_layer() {
        let secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let inner = STANDARD.encode(secret);
        let outer = STANDARD.encode(&inner);
        let layers = decode_layers(outer.as_bytes(), 32);
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
        let layers = decode_layers(encoded.as_bytes(), 32);
        assert!(layers.iter().any(|l| l == secret.as_bytes()));
    }

    #[test]
    fn depth_limit_honoured() {
        let secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut encoded = STANDARD.encode(secret);
        for _ in 0..10 {
            encoded = STANDARD.encode(&encoded);
        }
        let layers = decode_layers(encoded.as_bytes(), 3);
        assert!(layers.len() <= 4); // original + up to 3 decoded
    }

    #[test]
    fn garbage_input_returns_original() {
        let garbage = b"\x00\x01\x02\x03";
        let layers = decode_layers(garbage, 32);
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0], garbage);
    }

    #[test]
    fn empty_input() {
        let layers = decode_layers(b"", 32);
        assert_eq!(layers.len(), 1);
        assert!(layers[0].is_empty());
    }

    #[test]
    fn normal_text_no_extra_layers() {
        let text = b"Hello, this is normal text without any encoding.";
        let layers = decode_layers(text, 32);
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
        let layers = decode_layers(envelope.as_bytes(), 32);
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
        let layers = decode_layers(envelope.as_bytes(), 32);
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
        let layers = decode_layers(envelope.as_bytes(), 32);
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
        let layers = decode_layers(envelope, 32);
        // Whole-buffer decoders should also bail (envelope isn't pure
        // base64) so we expect exactly 1 layer: the original.
        assert_eq!(layers.len(), 1);
    }

    #[test]
    fn dedup_cycles_do_not_explode() {
        // Pathological: a string whose decode produces itself. The
        // fingerprint dedup should make the BFS terminate immediately
        // without re-queueing the same payload.
        let s = b"YWJjZA==";
        let layers = decode_layers(s, 32);
        assert!(layers.len() <= 32, "got {} layers", layers.len());
    }
}
