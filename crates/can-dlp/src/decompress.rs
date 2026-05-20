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
            // Skip the lie-detection warning when the claim is a comma-
            // separated stack — sniff only inspects the outermost
            // layer, and a stack like `gzip, deflate` is gzip-on-the-
            // wire, so the sniff and one of the claim tokens always
            // match.
            Some(claim) if !claim.contains(',') && !encoding_matches_sniff(claim, actual) => {
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

    // Per RFC 7231 §3.1.2.2 a Content-Encoding header lists the
    // encodings "in the order in which they were applied" by the
    // sender, so the receiver decodes in REVERSE order to recover the
    // original bytes. A claim of `gzip, deflate` means
    // `deflate(gzip(payload))` went on the wire — peel deflate, then
    // peel gzip. Bounded at MAX_LAYERS so a hostile
    // `gzip,gzip,gzip,…` header can't drive us into a CPU/RAM hole.
    const MAX_LAYERS: usize = 4;
    let Some(claim) = claimed else {
        return data.to_vec();
    };
    let layers: Vec<&str> = claim
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if layers.is_empty() {
        return data.to_vec();
    }
    let mut current = data.to_vec();
    for (i, layer) in layers.iter().rev().enumerate() {
        if i >= MAX_LAYERS {
            warn!(
                "dlp: Content-Encoding stack exceeded {MAX_LAYERS} layers — stopping decompression"
            );
            break;
        }
        let Some(decoded) = decompress_layer(layer, &current) else {
            // A claimed layer that doesn't actually decode (e.g. claim
            // says `gzip` but the bytes aren't gzip) leaves the
            // partial result in place — the scanner still gets to see
            // whatever bytes we have, which is no worse than the
            // single-layer fallback.
            return current;
        };
        current = decoded;
    }
    current
}

fn decompress_layer(layer: &str, data: &[u8]) -> Option<Vec<u8>> {
    match layer {
        "gzip" | "x-gzip" => try_gzip(data),
        "deflate" => try_deflate(data),
        "br" => try_brotli(data),
        "zstd" => try_zstd(data),
        // `identity` is a no-op encoding per RFC 7231 — just pass
        // through. Any other value is unknown to us; return None so
        // the caller stops layer-peeling.
        "identity" => Some(data.to_vec()),
        _ => None,
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
    // HTTP `Content-Encoding: deflate` is historically ambiguous: most
    // clients (Python's `zlib.compress`, browsers, requests, libcurl)
    // ship zlib-wrapped DEFLATE (RFC 1950 — 2-byte header + DEFLATE +
    // adler32), but the literal RFC reading is raw DEFLATE (RFC 1951).
    // Try zlib first; on failure fall back to raw so we don't regress
    // the few clients that send the raw stream.
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::new();
    if decoder.read_to_end(&mut out).is_ok() {
        return Some(out);
    }
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
    fn deflate_raw_round_trip() {
        // Raw DEFLATE (RFC 1951) — the strict reading of HTTP `deflate`.
        let original = b"npm_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress(&compressed, Some("deflate"));
        assert_eq!(decompressed, original);
    }

    #[test]
    fn deflate_zlib_round_trip() {
        // Zlib-wrapped DEFLATE (RFC 1950) — what Python's `zlib.compress`
        // and most real HTTP clients send under `Content-Encoding: deflate`.
        // Regression: the previous decoder only handled raw DEFLATE, so
        // bodies from Python clients (e.g. the dlp-test.py fuzzer) were
        // opaque to the scanner and every json_body+deflate case leaked.
        let original = b"AKIA0123456789ABCDEF";
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(
            &compressed[..2],
            &[0x78, 0x9c],
            "sanity: zlib header expected"
        );

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
    fn multi_layer_content_encoding_is_unwrapped_in_reverse() {
        // RFC 7231 §3.1.2.2: encodings are listed in the order they
        // were applied. `gzip, deflate` therefore means
        // `deflate(gzip(payload))` on the wire — peel deflate first,
        // then gzip. Before this fix the decoder treated the
        // whole comma-separated string as one unknown encoding and
        // dropped to opaque-bytes, letting a stacked-encoding exfil
        // bypass the scanner.
        let original = b"ghp_LAYEREDsomething1234567890ABCD";
        let gzipped = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(original).unwrap();
            e.finish().unwrap()
        };
        let stacked = {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(&gzipped).unwrap();
            e.finish().unwrap()
        };
        let out = decompress(&stacked, Some("gzip, deflate"));
        assert_eq!(out, original);
    }

    #[test]
    fn multi_layer_with_identity_is_a_noop() {
        let original = b"plaintext payload";
        let out = decompress(original, Some("identity"));
        assert_eq!(out, original);
        let out2 = decompress(original, Some("identity, identity"));
        assert_eq!(out2, original);
    }

    #[test]
    fn multi_layer_unknown_encoding_stops_peel_safely() {
        // `weird-encoding` is unknown; the decoder leaves the bytes
        // as-is rather than panicking or dropping the buffer.
        let bytes = b"some bytes";
        let out = decompress(bytes, Some("weird-encoding, gzip"));
        assert_eq!(out, bytes);
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
