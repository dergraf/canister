//! Property-based fuzz harness for the DLP pipeline.
//!
//! Generates `(canary × transform-chain × channel)` triples and asserts
//! that the scanner detects every canary regardless of how it was
//! encoded or where in the request it was stashed. This is the in-tree
//! replacement for re-running `dlp-test.py` manually.
//!
//! ## Generator discipline
//!
//! Transform chains are split into two layers because the scanner's
//! design partitions transforms by composition rules (see
//! [`can_dlp::transforms::TransformKind`]):
//!
//! - **Compositional** ops (Base64Std, Base64Url, Hex, Percent, Gzip,
//!   Zlib, Zstd) walk through the BFS in `decode_layers` and stack
//!   freely. The harness allows 0..=3 of them.
//! - **Inner-only** ops (Reverse, Rot13, InterleaveSep) are applied
//!   *flat* in `scan_text` (LastResort / Normalize). They can only be
//!   detected if they sit at the bottom of the chain — i.e., applied
//!   *first* to the raw canary — so the BFS can peel back to a layer
//!   on which `scan_text` then fires. Allowing them outside that slot
//!   would produce known-impossible chains and turn the harness into
//!   a flaky "find the design limit" generator, not a regression
//!   guard.
//!
//! The result: every generated chain is *catchable by design*. A
//! failing case means a real regression, not a known limitation.

use base64::Engine;
use can_dlp::{DetectorId, DlpScanner, ScanVerdict, StringSource};
use proptest::prelude::*;
use std::collections::HashMap;
use std::io::Write;

const SESSION_CANARY: &str = "CANISTERTOKENSESSIONPROPTEST00";

// ──────────────────────────────────────────────────────────────────────
// Canaries — drawn from the detector registry's positive test vectors.
// Each entry is `(detector_id, raw_token_bytes)`. We pick fixed strings
// (not randomly generated) so the proptest's shrunken counterexamples
// are stable and the regression file replays deterministically.
// ──────────────────────────────────────────────────────────────────────

fn known_canaries() -> Vec<(&'static str, &'static [u8])> {
    vec![
        ("github_pat", b"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("npm_token", b"npm_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"),
        ("aws_access_key", b"AKIA1234567890ABCDEF"),
        ("openai_key", b"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        (
            "anthropic_key",
            b"sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("google_api_key", b"AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("stripe_key", b"sk_live_AAAAAAAAAAAAAAAAAAAAAAAA"),
    ]
}

fn arb_canary() -> impl Strategy<Value = (&'static str, Vec<u8>)> {
    let entries = known_canaries();
    (0usize..entries.len()).prop_map(move |idx| {
        let (id, raw) = entries[idx];
        (id, raw.to_vec())
    })
}

// ──────────────────────────────────────────────────────────────────────
// Transform operations
// ──────────────────────────────────────────────────────────────────────

/// Compositional ops: each one's output is `decode_layers`-decodable by
/// a corresponding entry in the transform registry, so stacks compose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompOp {
    Base64Std,
    Base64Url,
    Hex,
    Percent,
    Gzip,
    Zlib,
    Zstd,
}

/// Inner-only ops: applied to the raw canary before any compositional
/// wrapping. The scanner picks them up via flat passes in `scan_text`
/// (Normalize / LastResort), not via the BFS, so they must sit at the
/// bottom of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnerOp {
    Reverse,
    Rot13,
    InterleaveSep(char),
}

#[derive(Debug, Clone)]
struct Chain {
    inner: Option<InnerOp>,
    comp: Vec<CompOp>,
}

fn arb_comp_op() -> impl Strategy<Value = CompOp> {
    prop_oneof![
        Just(CompOp::Base64Std),
        Just(CompOp::Base64Url),
        Just(CompOp::Hex),
        Just(CompOp::Percent),
        Just(CompOp::Gzip),
        Just(CompOp::Zlib),
        Just(CompOp::Zstd),
    ]
}

fn arb_inner_op() -> impl Strategy<Value = InnerOp> {
    prop_oneof![
        Just(InnerOp::Reverse),
        Just(InnerOp::Rot13),
        Just(InnerOp::InterleaveSep('-')),
        Just(InnerOp::InterleaveSep(' ')),
        Just(InnerOp::InterleaveSep('.')),
        Just(InnerOp::InterleaveSep('_')),
    ]
}

fn arb_chain(max_comp: usize) -> impl Strategy<Value = Chain> {
    (
        proptest::option::of(arb_inner_op()),
        proptest::collection::vec(arb_comp_op(), 0..=max_comp),
    )
        .prop_map(|(inner, comp)| Chain { inner, comp })
}

fn apply_inner(op: InnerOp, data: &[u8]) -> Vec<u8> {
    match op {
        InnerOp::Reverse => {
            let mut v = data.to_vec();
            v.reverse();
            v
        }
        InnerOp::Rot13 => data
            .iter()
            .map(|b| match b {
                b'A'..=b'Z' => b'A' + (b - b'A' + 13) % 26,
                b'a'..=b'z' => b'a' + (b - b'a' + 13) % 26,
                _ => *b,
            })
            .collect(),
        InnerOp::InterleaveSep(sep) => {
            let mut out = Vec::with_capacity(data.len() * 2);
            for (i, b) in data.iter().enumerate() {
                if i > 0 {
                    out.push(sep as u8);
                }
                out.push(*b);
            }
            out
        }
    }
}

fn apply_comp(op: CompOp, data: &[u8]) -> Vec<u8> {
    match op {
        CompOp::Base64Std => base64::engine::general_purpose::STANDARD
            .encode(data)
            .into_bytes(),
        CompOp::Base64Url => base64::engine::general_purpose::URL_SAFE
            .encode(data)
            .into_bytes(),
        CompOp::Hex => {
            let mut out = String::with_capacity(data.len() * 2);
            for b in data {
                out.push_str(&format!("{b:02x}"));
            }
            out.into_bytes()
        }
        CompOp::Percent => {
            // Force-encode every byte; the decoder accepts identity %XX
            // sequences. Skipping ascii passthrough makes the encoded
            // text unambiguously a percent-string and keeps the input
            // out of the "looks like b64" fragment-pass paths.
            let mut out = String::with_capacity(data.len() * 3);
            for b in data {
                out.push_str(&format!("%{b:02X}"));
            }
            out.into_bytes()
        }
        CompOp::Gzip => {
            // mtime=0 keeps output byte-stable across runs (proptest
            // regression file works correctly).
            let mut enc = flate2::GzBuilder::new()
                .mtime(0)
                .write(Vec::new(), flate2::Compression::default());
            enc.write_all(data).expect("gzip write");
            enc.finish().expect("gzip finish")
        }
        CompOp::Zlib => {
            let mut enc =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(data).expect("zlib write");
            enc.finish().expect("zlib finish")
        }
        CompOp::Zstd => zstd::encode_all(data, 0).expect("zstd encode"),
    }
}

fn apply_chain(canary: &[u8], chain: &Chain) -> Vec<u8> {
    let mut buf = if let Some(op) = chain.inner {
        apply_inner(op, canary)
    } else {
        canary.to_vec()
    };
    for op in &chain.comp {
        buf = apply_comp(*op, &buf);
    }
    buf
}

// ──────────────────────────────────────────────────────────────────────
// Channels — where in the request to stash the encoded canary.
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Channel {
    HeaderValue {
        name: String,
    },
    UriPath,
    UriQuery {
        key: String,
    },
    JsonBodyString {
        depth: u8,
        key: String,
    },
    /// HTTP/1.1 chunked trailer — was a complete bypass before
    /// the proxy started extracting `collected.trailers()`.
    Trailer {
        name: String,
    },
    /// `application/x-www-form-urlencoded` body, key-attributed.
    FormUrlEncoded {
        key: String,
    },
    /// `multipart/form-data` body part, attributed to its
    /// Content-Disposition `name=`.
    Multipart {
        name: String,
    },
    /// XML text node nested inside an element.
    XmlText {
        element: String,
    },
    /// XML attribute value on a root element.
    XmlAttr {
        element: String,
        attr: String,
    },
}

fn arb_channel() -> impl Strategy<Value = Channel> {
    // The HeaderValue arm includes every header an attacker can
    // realistically control end-to-end, including the ones the
    // earlier skip-list exempted from scanning (User-Agent, Cookie,
    // Referer, Origin, Forwarded, Cache-Control). Each one was a
    // real exfil vector before the skip-list was removed, and pinning
    // them as proptest channels guards against a regression where a
    // future "skip these for performance" PR re-introduces the gap.
    prop_oneof![
        Just(Channel::HeaderValue {
            name: "X-Custom".to_string()
        }),
        Just(Channel::HeaderValue {
            name: "Authorization".to_string()
        }),
        Just(Channel::HeaderValue {
            name: "Cookie".to_string()
        }),
        Just(Channel::HeaderValue {
            name: "User-Agent".to_string()
        }),
        Just(Channel::HeaderValue {
            name: "Referer".to_string()
        }),
        Just(Channel::HeaderValue {
            name: "Origin".to_string()
        }),
        Just(Channel::HeaderValue {
            name: "Forwarded".to_string()
        }),
        Just(Channel::HeaderValue {
            name: "Cache-Control".to_string()
        }),
        Just(Channel::UriPath),
        Just(Channel::UriQuery {
            key: "q".to_string()
        }),
        Just(Channel::UriQuery {
            key: "token".to_string()
        }),
        Just(Channel::JsonBodyString {
            depth: 0,
            key: "data".to_string()
        }),
        Just(Channel::JsonBodyString {
            depth: 2,
            key: "secret".to_string()
        }),
        // Trailer / form / multipart / xml channels: PR4 plug for
        // payload types the old scanner ignored. Each was a complete
        // bypass before the structured walkers landed.
        Just(Channel::Trailer {
            name: "X-Sig".to_string()
        }),
        Just(Channel::Trailer {
            name: "X-Checksum".to_string()
        }),
        Just(Channel::FormUrlEncoded {
            key: "token".to_string()
        }),
        Just(Channel::FormUrlEncoded {
            key: "api_key".to_string()
        }),
        Just(Channel::Multipart {
            name: "api_key".to_string()
        }),
        Just(Channel::Multipart {
            name: "file".to_string()
        }),
        Just(Channel::XmlText {
            element: "Token".to_string()
        }),
        Just(Channel::XmlAttr {
            element: "Cfg".to_string(),
            attr: "key".to_string(),
        }),
    ]
}

/// `(headers, uri, body, content_type, trailers)`. Trailers are
/// non-empty only for the `Trailer` channel; everything else passes
/// an empty Vec.
type BuiltRequest = (
    Vec<(String, String)>,
    String,
    Vec<u8>,
    Option<String>,
    Vec<(String, String)>,
);

/// Build a synthetic request shaped by `channel` with `payload` placed
/// at the indicated spot.
fn build_request(channel: &Channel, payload: &[u8]) -> BuiltRequest {
    let host = ("Host".to_string(), "evil.example.com".to_string());
    match channel {
        Channel::HeaderValue { name } => {
            let value = String::from_utf8_lossy(payload).into_owned();
            (
                vec![host, (name.clone(), value)],
                "/".to_string(),
                Vec::new(),
                None,
                Vec::new(),
            )
        }
        Channel::UriPath => {
            let escaped = percent_escape_path(payload);
            (
                vec![host],
                format!("/api/v1/{escaped}"),
                Vec::new(),
                None,
                Vec::new(),
            )
        }
        Channel::UriQuery { key } => {
            let escaped = percent_escape_query(payload);
            (
                vec![host],
                format!("/api?{key}={escaped}"),
                Vec::new(),
                None,
                Vec::new(),
            )
        }
        Channel::JsonBodyString { depth, key } => {
            let leaf = String::from_utf8_lossy(payload).into_owned();
            let mut value = serde_json::json!({ key: leaf });
            for i in 0..*depth {
                value = serde_json::json!({ format!("layer{i}"): value });
            }
            let body = serde_json::to_vec(&value).expect("json encode");
            (
                vec![host],
                "/v1/upload".to_string(),
                body,
                Some("application/json".to_string()),
                Vec::new(),
            )
        }
        Channel::Trailer { name } => {
            let value = String::from_utf8_lossy(payload).into_owned();
            (
                vec![host],
                "/".to_string(),
                b"chunk-body".to_vec(),
                None,
                vec![(name.clone(), value)],
            )
        }
        Channel::FormUrlEncoded { key } => {
            let escaped = percent_escape_query(payload);
            let body = format!("name=alice&{key}={escaped}&other=value").into_bytes();
            (
                vec![host],
                "/v1/submit".to_string(),
                body,
                Some("application/x-www-form-urlencoded".to_string()),
                Vec::new(),
            )
        }
        Channel::Multipart { name } => {
            // Synthesise a minimal RFC 7578 body. The walker only
            // looks at Content-Disposition's `name=`, so attribute
            // accordingly. Payload is wrapped as raw bytes so binary
            // chains (gzip etc.) survive — multipart parts are
            // opaque.
            let mut body = Vec::new();
            body.extend_from_slice(b"--bnd\r\n");
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(payload);
            body.extend_from_slice(b"\r\n--bnd--\r\n");
            (
                vec![host],
                "/v1/upload".to_string(),
                body,
                Some("multipart/form-data; boundary=bnd".to_string()),
                Vec::new(),
            )
        }
        Channel::XmlText { element } => {
            let leaf = String::from_utf8_lossy(payload).into_owned();
            // Escape `<` and `>` so a payload containing tag-shaped
            // bytes doesn't confuse the (deliberately minimal) walker
            // and bias the test toward "we caught it via BodyRaw".
            let escaped = xml_escape_text(&leaf);
            let body = format!("<root><{element}>{escaped}</{element}></root>").into_bytes();
            (
                vec![host],
                "/v1/upload".to_string(),
                body,
                Some("application/xml".to_string()),
                Vec::new(),
            )
        }
        Channel::XmlAttr { element, attr } => {
            let leaf = String::from_utf8_lossy(payload).into_owned();
            let escaped = xml_escape_attr(&leaf);
            let body = format!("<{element} {attr}=\"{escaped}\"/>").into_bytes();
            (
                vec![host],
                "/v1/upload".to_string(),
                body,
                Some("application/xml".to_string()),
                Vec::new(),
            )
        }
    }
}

fn xml_escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_escape_attr(s: &str) -> String {
    xml_escape_text(s).replace('"', "&quot;")
}

fn percent_escape_path(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    for b in data {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_escape_query(data: &[u8]) -> String {
    // Same as path but also escape `&` and `=` to keep the query
    // structure unambiguous for the splitter.
    let mut out = String::with_capacity(data.len() * 3);
    for b in data {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ──────────────────────────────────────────────────────────────────────
// Scanner setup
// ──────────────────────────────────────────────────────────────────────

/// Skip the test case if it isn't a meaningful regression check.
/// Two classes of unrepresentable inputs are filtered out:
///
/// 1. **Wire-format rejects** — an HTTP parser drops binary header
///    values; a JSON serializer can't round-trip non-UTF-8 as a JSON
///    string. URI path/query carry binary safely via percent-encoding.
/// 2. **Ambiguous interleavings** — `InterleaveSep(c)` on a canary
///    that already contains `c` is genuinely ambiguous: the scanner
///    has no way to tell which `c` glyphs are "real prefix
///    characters" (`ghp_`, `sk-ant-`, `sk_live_`) vs which are
///    interleaved noise. Stripping all of them destroys the prefix
///    and the regex can't anchor. This is a known design limit, not
///    a regression — without a per-detector oracle there is no
///    sound recovery.
fn skip_if_unrepresentable(
    channel: &Channel,
    chain: &Chain,
    raw: &[u8],
    encoded: &[u8],
) -> Result<(), TestCaseError> {
    if let Some(InnerOp::InterleaveSep(sep)) = chain.inner {
        if raw.contains(&(sep as u8)) {
            return Err(TestCaseError::reject(
                "InterleaveSep char also appears in the canary — ambiguous",
            ));
        }
    }
    let needs_text = matches!(
        channel,
        Channel::HeaderValue { .. }
            | Channel::JsonBodyString { .. }
            | Channel::Trailer { .. }
            | Channel::FormUrlEncoded { .. }
            | Channel::XmlText { .. }
            | Channel::XmlAttr { .. }
    );
    if needs_text && std::str::from_utf8(encoded).is_err() {
        return Err(TestCaseError::reject(
            "binary payload cannot be carried by a text-only channel",
        ));
    }
    if matches!(
        channel,
        Channel::HeaderValue { .. } | Channel::Trailer { .. }
    ) && encoded
        .iter()
        .any(|b| *b == 0 || *b == b'\r' || *b == b'\n')
    {
        return Err(TestCaseError::reject(
            "control-character payload cannot be carried in a header / trailer value",
        ));
    }
    // Form-urlencoded values can't contain `&` or `=` raw — those are
    // structural delimiters. We percent-escape via `percent_escape_query`
    // in build_request, so any byte is technically representable.
    // Multipart bodies are opaque byte containers; no per-byte filter.
    Ok(())
}

fn fresh_scanner() -> DlpScanner {
    let scopes: HashMap<String, Vec<String>> = HashMap::new();
    DlpScanner::new(Vec::new(), &scopes, 16, true, false).expect("scanner")
}

fn find_verdict<'a>(
    verdicts: &'a [ScanVerdict],
    expected: &'static str,
) -> Option<&'a ScanVerdict> {
    let target = DetectorId::new(expected);
    verdicts.iter().find(|v| v.detector == target)
}

// ──────────────────────────────────────────────────────────────────────
// Main property: any encoded canary on any channel must be detected.
// ──────────────────────────────────────────────────────────────────────

proptest! {
    // Case count is tuned for CI: 128 cases × chain depth 3 lands
    // around ~5s in release and ~40s in debug. Override at the shell
    // with `PROPTEST_CASES=1024` for a deeper sweep before merging
    // risky DLP changes.
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_shrink_iters: 4096,
        .. ProptestConfig::default()
    })]

    #[test]
    fn any_encoded_canary_is_detected(
        (det, raw) in arb_canary(),
        chain in arb_chain(3),
        chan in arb_channel(),
    ) {
        let encoded = apply_chain(&raw, &chain);
        // Skip channel × payload combinations the wire format can't
        // actually represent. A real HTTP parser rejects binary header
        // values; a JSON serializer can't round-trip non-UTF-8 bytes
        // as a JSON string. URI path/query carry binary safely via
        // percent-encoding (handled in build_request).
        skip_if_unrepresentable(&chan, &chain, &raw, &encoded)?;

        let (headers, uri, body, content_type, trailers) =
            build_request(&chan, &encoded);
        let scanner = fresh_scanner();
        let verdicts = scanner.scan_request_with_trailers(
            &headers,
            &uri,
            &body,
            content_type.as_deref(),
            None,
            &trailers,
            "evil.example.com",
        );

        prop_assert!(
            find_verdict(&verdicts, det).is_some(),
            "missed detector={det} chain={chain:?} channel={chan:?} encoded_len={}",
            encoded.len(),
        );
    }
}

// ──────────────────────────────────────────────────────────────────────
// Source attribution invariant: a verdict's source must point at a
// channel that's plausible for the way we stashed the canary.
// ──────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        max_shrink_iters: 2048,
        .. ProptestConfig::default()
    })]

    #[test]
    fn verdict_source_matches_channel(
        (det, raw) in arb_canary(),
        chain in arb_chain(2),
        chan in arb_channel(),
    ) {
        let encoded = apply_chain(&raw, &chain);
        skip_if_unrepresentable(&chan, &chain, &raw, &encoded)?;
        let (headers, uri, body, content_type, trailers) =
            build_request(&chan, &encoded);
        let scanner = fresh_scanner();
        let verdicts = scanner.scan_request_with_trailers(
            &headers,
            &uri,
            &body,
            content_type.as_deref(),
            None,
            &trailers,
            "evil.example.com",
        );
        let Some(v) = find_verdict(&verdicts, det) else {
            // Detection itself is covered by the other property;
            // skip the attribution check on misses.
            return Ok(());
        };

        match (&chan, &v.source) {
            (Channel::HeaderValue { name }, Some(StringSource::HeaderValue { name: got })) => {
                prop_assert_eq!(name.to_ascii_lowercase(), got.to_ascii_lowercase());
            }
            (Channel::UriPath, Some(StringSource::UriPath { .. })) => {}
            (Channel::UriQuery { key }, Some(StringSource::UriQueryValue { key: got })) => {
                prop_assert_eq!(key, got);
            }
            (Channel::JsonBodyString { .. }, Some(StringSource::JsonString { .. })) => {}
            // Structured walkers each have their dedicated source
            // variant + a BodyRaw fallback for cases where the
            // payload itself confuses the walker (e.g. a multipart
            // body whose part bytes look like another boundary).
            (Channel::JsonBodyString { .. }, Some(StringSource::BodyRaw)) => {}
            (Channel::Trailer { name }, Some(StringSource::TrailerValue { name: got })) => {
                prop_assert_eq!(name, got);
            }
            (Channel::FormUrlEncoded { key }, Some(StringSource::FormValue { key: got })) => {
                prop_assert_eq!(key, got);
            }
            (Channel::FormUrlEncoded { .. }, Some(StringSource::BodyRaw)) => {}
            (Channel::Multipart { name }, Some(StringSource::Multipart { field })) => {
                prop_assert_eq!(name, field);
            }
            (Channel::Multipart { .. }, Some(StringSource::BodyRaw)) => {}
            (Channel::XmlText { element }, Some(StringSource::XmlText { path })) => {
                prop_assert!(path.ends_with(element.as_str()));
            }
            (
                Channel::XmlAttr { element, attr },
                Some(StringSource::XmlAttribute { path, name }),
            ) => {
                prop_assert!(path.ends_with(element.as_str()));
                prop_assert_eq!(attr, name);
            }
            (Channel::XmlText { .. } | Channel::XmlAttr { .. }, Some(StringSource::BodyRaw)) => {}
            (chan, src) => prop_assert!(
                false,
                "unexpected source for channel: chan={chan:?} src={src:?}"
            ),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Response-direction property: any encoded reflection of the session
// canary that a malicious upstream embeds in either a response header
// or the body must be caught. Mirrors the request-direction property
// but flipped to the response side, so the proptest harness covers
// both DLP directions equally.
// ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum ResponseChannel {
    /// Reflected via a response header (Set-Cookie, Location,
    /// X-Reflect — anything an attacker-controlled upstream can set).
    Header { name: String },
    /// Reflected via the response body (raw or JSON-wrapped).
    Body { json_wrap: bool },
}

fn arb_response_channel() -> impl Strategy<Value = ResponseChannel> {
    prop_oneof![
        Just(ResponseChannel::Header {
            name: "Set-Cookie".to_string()
        }),
        Just(ResponseChannel::Header {
            name: "Location".to_string()
        }),
        Just(ResponseChannel::Header {
            name: "X-Reflect".to_string()
        }),
        Just(ResponseChannel::Header {
            name: "Server".to_string()
        }),
        Just(ResponseChannel::Body { json_wrap: false }),
        Just(ResponseChannel::Body { json_wrap: true }),
    ]
}

fn build_response(
    channel: &ResponseChannel,
    payload: &[u8],
) -> (Vec<(String, String)>, Vec<u8>, Option<String>) {
    match channel {
        ResponseChannel::Header { name } => {
            let value = String::from_utf8_lossy(payload).into_owned();
            (
                vec![
                    ("Content-Type".to_string(), "text/plain".to_string()),
                    (name.clone(), value),
                ],
                b"ok".to_vec(),
                Some("text/plain".to_string()),
            )
        }
        ResponseChannel::Body { json_wrap: false } => (
            vec![("Content-Type".to_string(), "text/plain".to_string())],
            payload.to_vec(),
            Some("text/plain".to_string()),
        ),
        ResponseChannel::Body { json_wrap: true } => {
            let leaf = String::from_utf8_lossy(payload).into_owned();
            let value = serde_json::json!({ "data": { "echo": leaf } });
            (
                vec![("Content-Type".to_string(), "application/json".to_string())],
                serde_json::to_vec(&value).expect("json encode"),
                Some("application/json".to_string()),
            )
        }
    }
}

fn canary_scanner() -> DlpScanner {
    let scopes: HashMap<String, Vec<String>> = HashMap::new();
    DlpScanner::new(vec![SESSION_CANARY.to_string()], &scopes, 16, true, false)
        .expect("scanner with canary")
}

fn skip_response_unrepresentable(
    channel: &ResponseChannel,
    chain: &Chain,
    raw: &[u8],
    encoded: &[u8],
) -> Result<(), TestCaseError> {
    if let Some(InnerOp::InterleaveSep(sep)) = chain.inner {
        if raw.contains(&(sep as u8)) {
            return Err(TestCaseError::reject(
                "InterleaveSep char also appears in the canary — ambiguous",
            ));
        }
    }
    match channel {
        ResponseChannel::Header { .. } => {
            if std::str::from_utf8(encoded).is_err() {
                return Err(TestCaseError::reject(
                    "binary payload cannot be carried in a response header value",
                ));
            }
            if encoded
                .iter()
                .any(|b| *b == 0 || *b == b'\r' || *b == b'\n')
            {
                return Err(TestCaseError::reject(
                    "control-character payload cannot be carried in a header value",
                ));
            }
        }
        ResponseChannel::Body { json_wrap: true } => {
            if std::str::from_utf8(encoded).is_err() {
                return Err(TestCaseError::reject(
                    "binary payload cannot be embedded as a JSON string",
                ));
            }
        }
        ResponseChannel::Body { json_wrap: false } => {
            // Raw bodies carry any bytes.
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        max_shrink_iters: 4096,
        .. ProptestConfig::default()
    })]

    #[test]
    fn any_encoded_canary_reflected_in_response_is_detected(
        chain in arb_chain(3),
        chan in arb_response_channel(),
    ) {
        let raw = SESSION_CANARY.as_bytes();
        let encoded = apply_chain(raw, &chain);
        skip_response_unrepresentable(&chan, &chain, raw, &encoded)?;

        let (headers, body, content_type) = build_response(&chan, &encoded);
        let scanner = canary_scanner();
        let verdicts = scanner.scan_response(
            &headers,
            &body,
            content_type.as_deref(),
            None,
            "evil.example.com",
        );

        prop_assert!(
            verdicts.iter().any(|v| v.detector == DetectorId::new("canary_token")),
            "missed canary reflection: chain={chain:?} channel={chan:?} encoded_len={}",
            encoded.len(),
        );
    }
}
