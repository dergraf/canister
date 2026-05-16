use std::io::Read;

pub fn decompress(data: &[u8], content_encoding: Option<&str>) -> Vec<u8> {
    match content_encoding {
        Some("gzip") | Some("x-gzip") => try_gzip(data).unwrap_or_else(|| data.to_vec()),
        Some("deflate") => try_deflate(data).unwrap_or_else(|| data.to_vec()),
        Some("br") => try_brotli(data).unwrap_or_else(|| data.to_vec()),
        _ => data.to_vec(),
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
}
