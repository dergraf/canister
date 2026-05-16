use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};

pub fn decode_layers(data: &[u8], max_depth: usize) -> Vec<Vec<u8>> {
    let mut layers = vec![data.to_vec()];
    decode_recursive(data, max_depth, &mut layers);
    layers
}

fn decode_recursive(data: &[u8], remaining_depth: usize, layers: &mut Vec<Vec<u8>>) {
    if remaining_depth == 0 || data.len() < 4 {
        return;
    }

    type Decoder = fn(&[u8]) -> Option<Vec<u8>>;
    let decoders: &[Decoder] = &[
        try_base64_standard,
        try_base64_urlsafe,
        try_hex,
        try_percent_decode,
    ];

    for decoder in decoders {
        if let Some(decoded) = decoder(data) {
            if decoded != data && !decoded.is_empty() {
                layers.push(decoded.clone());
                decode_recursive(&decoded, remaining_depth - 1, layers);
                return;
            }
        }
    }
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
}
