use std::io::Read;

use tracing::warn;

pub fn decompress(data: &[u8], content_encoding: Option<&str>) -> Vec<u8> {
    let claimed = content_encoding.map(|s| s.to_ascii_lowercase());
    let sniffed = sniff_compression(data);

    // R12: emit a `dlp-evasion` warning when Content-Encoding lies about
    // the body's real magic bytes. This catches the case where an
    // attacker labels a body as `identity` but ships zstd-compressed
    // payload — the scanner would otherwise see opaque bytes and miss
    // the contained token.
    if let Some(actual) = sniffed {
        match claimed.as_deref() {
            Some(claim) if !encoding_matches_sniff(claim, actual) => {
                warn!(
                    "dlp-evasion: Content-Encoding mismatch — header={} actual={}",
                    claim,
                    actual.label()
                );
            }
            None => {
                // Body looks compressed but the request didn't say so —
                // try to decompress anyway. The scanner gets a better
                // chance to see the inner bytes.
                if let Some(decoded) = decompress_with(actual, data) {
                    warn!(
                        "dlp-evasion: undeclared {} body — decompressing for DLP scan",
                        actual.label()
                    );
                    return decoded;
                }
            }
            _ => {}
        }
    }

    match claimed.as_deref() {
        Some("gzip") | Some("x-gzip") => try_gzip(data).unwrap_or_else(|| data.to_vec()),
        Some("deflate") => try_deflate(data).unwrap_or_else(|| data.to_vec()),
        Some("br") => try_brotli(data).unwrap_or_else(|| data.to_vec()),
        Some("zstd") => try_zstd(data).unwrap_or_else(|| data.to_vec()),
        _ => data.to_vec(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compression {
    Gzip,
    Zstd,
}

impl Compression {
    fn label(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Zstd => "zstd",
        }
    }
}

fn sniff_compression(data: &[u8]) -> Option<Compression> {
    // gzip: 1F 8B
    if data.len() >= 2 && data[0] == 0x1F && data[1] == 0x8B {
        return Some(Compression::Gzip);
    }
    // zstd: 28 B5 2F FD
    if data.len() >= 4 && data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD {
        return Some(Compression::Zstd);
    }
    // Brotli has no fixed magic; we don't sniff it. Deflate is similarly
    // headerless — both are caught by the explicit Content-Encoding path.
    None
}

fn encoding_matches_sniff(claim: &str, sniff: Compression) -> bool {
    matches!(
        (claim, sniff),
        ("gzip" | "x-gzip", Compression::Gzip) | ("zstd", Compression::Zstd)
    )
}

fn decompress_with(comp: Compression, data: &[u8]) -> Option<Vec<u8>> {
    match comp {
        Compression::Gzip => try_gzip(data),
        Compression::Zstd => try_zstd(data),
    }
}

fn try_gzip(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

fn try_deflate(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = flate2::read::DeflateDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

fn try_brotli(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = brotli::Decompressor::new(data, 4096);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

fn try_zstd(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = zstd::stream::read::Decoder::new(data).ok()?;
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn gzip_round_trip() {
        let original = b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress(&compressed, Some("gzip"));
        assert_eq!(decompressed, original);
    }

    #[test]
    fn deflate_round_trip() {
        let original = b"npm_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress(&compressed, Some("deflate"));
        assert_eq!(decompressed, original);
    }

    #[test]
    fn brotli_round_trip() {
        let original = b"AKIA1234567890ABCDEF";
        let mut compressed = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut compressed, 4096, 6, 22);
            encoder.write_all(original).unwrap();
        }

        let decompressed = decompress(&compressed, Some("br"));
        assert_eq!(decompressed, original);
    }

    #[test]
    fn unknown_encoding_passthrough() {
        let data = b"just plain data";
        let result = decompress(data, Some("unknown"));
        assert_eq!(result, data);
    }

    #[test]
    fn no_encoding_passthrough() {
        let data = b"just plain data";
        let result = decompress(data, None);
        assert_eq!(result, data);
    }

    #[test]
    fn corrupt_gzip_returns_original() {
        let garbage = b"\x1f\x8b\x00\x00garbage";
        let result = decompress(garbage, Some("gzip"));
        assert_eq!(result, garbage);
    }

    #[test]
    fn zstd_round_trip() {
        let original = b"ghp_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
        let compressed = zstd::stream::encode_all(&original[..], 3).unwrap();
        let decompressed = decompress(&compressed, Some("zstd"));
        assert_eq!(decompressed, original);
    }

    #[test]
    fn undeclared_zstd_is_decompressed() {
        // R12: a body whose magic bytes are zstd but which carries no
        // Content-Encoding should still be decompressed so the scanner
        // gets a chance at the inner token (the proxy logs an evasion
        // warning).
        let original = b"npm_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
        let compressed = zstd::stream::encode_all(&original[..], 3).unwrap();
        let result = decompress(&compressed, None);
        assert_eq!(result, original);
    }

    #[test]
    fn mismatched_encoding_uses_claimed_path() {
        // If the header says `gzip` but the body is zstd, the decoder
        // sticks with the claimed encoding (returns the input unchanged
        // because gzip can't decode zstd) AND emits an evasion warning.
        // The warning is observed via the tracing layer in higher-level
        // tests; here we just verify no panic and a sane fallback.
        let original = b"some content";
        let zstd_data = zstd::stream::encode_all(&original[..], 3).unwrap();
        let result = decompress(&zstd_data, Some("gzip"));
        assert_eq!(result, zstd_data);
    }

    #[test]
    fn sniff_recognises_known_magic_bytes() {
        let gzip = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b"x").unwrap();
            e.finish().unwrap()
        };
        assert_eq!(sniff_compression(&gzip), Some(Compression::Gzip));

        let zstd_buf = zstd::stream::encode_all(&b"x"[..], 3).unwrap();
        assert_eq!(sniff_compression(&zstd_buf), Some(Compression::Zstd));

        assert_eq!(sniff_compression(b"plain text"), None);
        assert_eq!(sniff_compression(b""), None);
    }
}
