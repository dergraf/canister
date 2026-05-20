//! Structured string extraction for DLP scans.
//!
//! Replaces the "scan opaque bytes" model with a typed visitor that
//! surfaces every scannable string in a request, tagged with its
//! origin. Per-string scanning means a verdict can name *which* JSON
//! field / URI segment / header carried the credential — not just
//! "somewhere in the body."
//!
//! ## Layered design
//!
//! ```text
//!   request                       Vec<Extracted>                  Vec<ScanVerdict>
//!     │                                │                                │
//!     │   Extractor                    │   decode_layers + scan_text    │
//!     │ ──────────────►  StringSource  │ ──────────────────────────────►│
//!     │                  bytes         │                                │
//!     │                  ──────────    │                                │
//!     │                  HeaderName    │                                │
//!     │                  HeaderValue   │                                │
//!     │                  UriPath       │                                │
//!     │                  UriQueryKey   │                                │
//!     │                  UriQueryValue │                                │
//!     │                  JsonString    │                                │
//!     │                  JsonKey       │                                │
//!     │                  BodyRaw       │                                │
//!     │                  Multipart     │                                │
//! ```
//!
//! ## Cost discipline
//!
//! - JSON parse is hard-capped at [`Extractor::max_json_parse_bytes`].
//!   On failure (oversize body, malformed JSON, non-JSON content type)
//!   we emit a single `BodyRaw` `Extracted` covering the whole body —
//!   exactly the pre-refactor behaviour, so detection doesn't
//!   regress.
//! - URI splitting is O(uri.len()), no regex.
//! - `multipart/*` parsing is **not** implemented — the enum variant
//!   is reserved so future work can wire in a parser without changing
//!   call sites.

use std::borrow::Cow;

/// Where in the request a scanned string came from. Attached to every
/// [`crate::scanner::ScanVerdict`] so logs / alerts / future UI can
/// point to the exact location of a leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringSource {
    /// Header *name* (e.g. `X-Api-Key`). Some exfil channels stuff
    /// payload into the name itself.
    HeaderName,
    /// Header value with its name attached.
    HeaderValue { name: String },
    /// URI path segment (0-indexed, post-percent-decode).
    UriPath { segment_idx: usize },
    /// URI query parameter key (some exfil channels use the key).
    UriQueryKey,
    /// URI query parameter value, with its key attached.
    UriQueryValue { key: String },
    /// Body bytes treated as an opaque blob — used when structured
    /// parsing is impossible (non-JSON content type, JSON parse fails,
    /// body exceeds [`Extractor::max_json_parse_bytes`]). Preserves the
    /// pre-refactor opaque-bytes scan path.
    BodyRaw,
    /// String value found inside a parsed JSON body, with a dotted
    /// path (e.g. `user.tokens[0]`).
    JsonString { path: String },
    /// String *key* inside a parsed JSON body, with the path of its
    /// parent object.
    JsonKey { path: String },
    /// Reserved for a future multipart parser. PR2 emits `BodyRaw` for
    /// `multipart/*` content types.
    Multipart { field: String },
    /// HTTP/1.1 chunked trailer **name**. Trailers are sent after the
    /// body in a chunked transfer; before PR4 they were silently
    /// dropped by the proxy and bypassed DLP entirely.
    TrailerName,
    /// HTTP/1.1 chunked trailer value, with its name attached.
    TrailerValue { name: String },
    /// `application/x-www-form-urlencoded` body value with its form
    /// key attached. Parsed with the same percent-decode pass as
    /// query parameters so attackers can't hide a credential behind
    /// `%41%4B%49%41…`.
    FormValue { key: String },
    /// Form-urlencoded body key. Symmetric with [`Self::FormValue`];
    /// attackers can stuff credentials into the key as easily as the
    /// value.
    FormKey,
    /// Text node inside an XML body, with a slash-separated element
    /// path (e.g. `soap:Envelope/soap:Body/Auth/Token`).
    XmlText { path: String },
    /// XML attribute value, identified by element-path + attribute
    /// name (e.g. `Config/Endpoint@auth`). Many SAML / SOAP payloads
    /// stash bearer tokens in attributes.
    XmlAttribute { path: String, name: String },
}

impl StringSource {
    /// Short, log-friendly label. Used by tracing fields and verdict
    /// formatting.
    pub fn label(&self) -> Cow<'static, str> {
        match self {
            StringSource::HeaderName => Cow::Borrowed("header_name"),
            StringSource::HeaderValue { name } => Cow::Owned(format!("header:{name}")),
            StringSource::UriPath { segment_idx } => Cow::Owned(format!("uri_path[{segment_idx}]")),
            StringSource::UriQueryKey => Cow::Borrowed("uri_query_key"),
            StringSource::UriQueryValue { key } => Cow::Owned(format!("uri_query:{key}")),
            StringSource::BodyRaw => Cow::Borrowed("body_raw"),
            StringSource::JsonString { path } => Cow::Owned(format!("json:{path}")),
            StringSource::JsonKey { path } => Cow::Owned(format!("json_key:{path}")),
            StringSource::Multipart { field } => Cow::Owned(format!("multipart:{field}")),
            StringSource::TrailerName => Cow::Borrowed("trailer_name"),
            StringSource::TrailerValue { name } => Cow::Owned(format!("trailer:{name}")),
            StringSource::FormValue { key } => Cow::Owned(format!("form:{key}")),
            StringSource::FormKey => Cow::Borrowed("form_key"),
            StringSource::XmlText { path } => Cow::Owned(format!("xml:{path}")),
            StringSource::XmlAttribute { path, name } => Cow::Owned(format!("xml:{path}@{name}")),
        }
    }
}

/// A single scannable string with its provenance. Bytes may be borrowed
/// from the request (for header values, URI segments) or owned (for
/// percent-decoded segments, JSON values).
#[derive(Debug)]
pub struct Extracted<'a> {
    pub source: StringSource,
    pub bytes: Cow<'a, [u8]>,
}

/// Default cap on the body size we'll feed to `serde_json::from_slice`.
/// Bodies larger than this fall back to a single `BodyRaw` extraction —
/// preserves detection while bounding parse cost on hostile inputs.
pub const DEFAULT_MAX_JSON_PARSE_BYTES: usize = 1024 * 1024;

/// Pulls scannable strings out of HTTP request shapes (headers, URI,
/// body). Stateless; cheap to construct. Configure once per scanner.
#[derive(Debug, Clone)]
pub struct Extractor {
    /// Hard cap on bytes fed to `serde_json::from_slice`. Bodies above
    /// this fall back to `BodyRaw`. 1 MiB by default.
    pub max_json_parse_bytes: usize,
    /// If true, header names are emitted as `HeaderName` extractions.
    /// The fuzzer has a `header_name` exfil channel; production traffic
    /// almost never carries secrets in names, but the cost is one
    /// extra extraction per header.
    pub include_header_names: bool,
}

impl Default for Extractor {
    fn default() -> Self {
        Self {
            max_json_parse_bytes: DEFAULT_MAX_JSON_PARSE_BYTES,
            include_header_names: true,
        }
    }
}

impl Extractor {
    /// Yield one [`Extracted`] per HTTP/1.1 chunked **trailer** (the
    /// headers that arrive *after* the body in a chunked transfer).
    /// Functionally identical to [`Self::extract_headers`] but tags
    /// the source as `Trailer*` so logs distinguish where the leak
    /// happened. Trailers were a complete bypass before they were
    /// wired into the scanner — see `crates/can-proxy/src/server/request.rs`.
    pub fn extract_trailers<'a>(&self, trailers: &'a [(String, String)]) -> Vec<Extracted<'a>> {
        let mut out = Vec::with_capacity(trailers.len() * 2);
        for (name, value) in trailers {
            if self.include_header_names {
                out.push(Extracted {
                    source: StringSource::TrailerName,
                    bytes: Cow::Borrowed(name.as_bytes()),
                });
            }
            out.push(Extracted {
                source: StringSource::TrailerValue { name: name.clone() },
                bytes: Cow::Borrowed(value.as_bytes()),
            });
        }
        out
    }

    /// Yield one [`Extracted`] per header value (and per header name
    /// if [`Self::include_header_names`]). **Every** header is
    /// emitted — there is no skip-list. Earlier revisions exempted
    /// "protocol" headers (`User-Agent`, `Cookie`, `Referer`,
    /// `Forwarded`, etc.) on the assumption that they don't carry
    /// secrets, but those are exactly the headers an attacker
    /// controls end-to-end and the most plausible exfiltration
    /// channels for a compromised sandboxed worker. Detector regexes
    /// anchor on specific credential prefixes (`ghp_`, `AKIA`,
    /// `sk-ant-`, …), so the false-positive cost of scanning, say,
    /// `Content-Length: 1234` is effectively zero.
    pub fn extract_headers<'a>(&self, headers: &'a [(String, String)]) -> Vec<Extracted<'a>> {
        let mut out = Vec::with_capacity(headers.len() * 2);
        for (name, value) in headers {
            if self.include_header_names {
                out.push(Extracted {
                    source: StringSource::HeaderName,
                    bytes: Cow::Borrowed(name.as_bytes()),
                });
            }
            out.push(Extracted {
                source: StringSource::HeaderValue { name: name.clone() },
                bytes: Cow::Borrowed(value.as_bytes()),
            });
        }
        out
    }

    /// Split URI into path segments and query (key, value) pairs.
    /// Percent-decodes each piece once. Falls back to a single
    /// `BodyRaw` containing the whole URI bytes on malformed inputs
    /// (e.g. invalid UTF-8 after percent-decode) — preserves the
    /// pre-refactor opaque-bytes scan as a safety net.
    pub fn extract_uri<'a>(&self, uri: &'a str) -> Vec<Extracted<'a>> {
        let mut out = Vec::new();

        // Locate the path-query-fragment boundaries without parsing
        // scheme/authority — proxy URIs come in both absolute
        // (`https://h/p?q`) and origin-form (`/p?q`) shapes.
        let after_scheme = match uri.find("://") {
            Some(i) => match uri[i + 3..].find('/') {
                Some(j) => &uri[i + 3 + j..],
                None => "/",
            },
            None => uri,
        };

        // Drop fragment.
        let no_frag = match after_scheme.find('#') {
            Some(i) => &after_scheme[..i],
            None => after_scheme,
        };

        let (path, query) = match no_frag.find('?') {
            Some(i) => (&no_frag[..i], Some(&no_frag[i + 1..])),
            None => (no_frag, None),
        };

        for (idx, seg) in path.split('/').filter(|s| !s.is_empty()).enumerate() {
            let decoded = percent_encoding::percent_decode_str(seg).collect::<Vec<u8>>();
            out.push(Extracted {
                source: StringSource::UriPath { segment_idx: idx },
                bytes: Cow::Owned(decoded),
            });
        }

        if let Some(q) = query {
            for pair in q.split('&').filter(|s| !s.is_empty()) {
                let (key, value) = match pair.find('=') {
                    Some(i) => (&pair[..i], Some(&pair[i + 1..])),
                    None => (pair, None),
                };
                let key_decoded = percent_encoding::percent_decode_str(key).collect::<Vec<u8>>();
                if !key_decoded.is_empty() {
                    out.push(Extracted {
                        source: StringSource::UriQueryKey,
                        bytes: Cow::Owned(key_decoded.clone()),
                    });
                }
                if let Some(v) = value {
                    let value_decoded =
                        percent_encoding::percent_decode_str(v).collect::<Vec<u8>>();
                    // Tag the value with the *decoded* key so logs
                    // read naturally (`uri_query:token` not
                    // `uri_query:%74oken`).
                    let key_str = String::from_utf8(key_decoded)
                        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
                    out.push(Extracted {
                        source: StringSource::UriQueryValue { key: key_str },
                        bytes: Cow::Owned(value_decoded),
                    });
                }
            }
        }

        // Always include the raw URI as a fallback BodyRaw-ish layer
        // so encoded payloads spanning segment boundaries (e.g. a b64
        // canary that contains `/`) still reach the decode pipeline.
        // Layer dedup in `decode_layers` collapses duplicates with the
        // structured per-segment extractions.
        out.push(Extracted {
            source: StringSource::BodyRaw,
            bytes: Cow::Borrowed(uri.as_bytes()),
        });

        out
    }

    /// Extract scannable strings from a request body, dispatching by
    /// Content-Type:
    ///
    /// - `application/json` / `*+json` / `text/json` — JSON walker
    ///   with dotted-path attribution.
    /// - `application/x-www-form-urlencoded` — form walker with
    ///   key-attributed values.
    /// - `multipart/*` — multipart walker with per-part attribution.
    /// - `application/xml` / `text/xml` / `*+xml` — XML walker with
    ///   element-path + attribute attribution.
    /// - Anything else (binary, unknown type, parse failure): emit a
    ///   single `BodyRaw` extraction with the whole body. The
    ///   detector regexes still fire on raw bytes — structured
    ///   walkers improve attribution, not detection.
    ///
    /// **Every** structured walker *also* appends a `BodyRaw` entry
    /// covering the whole body, so encoded payloads that cross
    /// structural boundaries (a canary spanning two adjacent JSON
    /// strings, or two consecutive form values) still reach the
    /// decoder.
    pub fn extract_body<'a>(
        &self,
        body: &'a [u8],
        content_type: Option<&str>,
    ) -> Vec<Extracted<'a>> {
        let mut out = Vec::new();

        // JSON
        if is_json_content_type(content_type) && body.len() <= self.max_json_parse_bytes {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                walk_json_value(&value, String::new(), &mut out);
                if !out.is_empty() {
                    out.push(Extracted {
                        source: StringSource::BodyRaw,
                        bytes: Cow::Borrowed(body),
                    });
                    return out;
                }
            }
        }

        // Form-urlencoded
        if is_form_urlencoded(content_type) {
            walk_form_urlencoded(body, &mut out);
            out.push(Extracted {
                source: StringSource::BodyRaw,
                bytes: Cow::Borrowed(body),
            });
            return out;
        }

        // Multipart
        if let Some(boundary) = multipart_boundary(content_type) {
            walk_multipart(body, &boundary, &mut out);
            out.push(Extracted {
                source: StringSource::BodyRaw,
                bytes: Cow::Borrowed(body),
            });
            return out;
        }

        // XML
        if is_xml_content_type(content_type) {
            walk_xml(body, &mut out);
            // The walker may legitimately emit zero entries on inputs
            // that don't have any text nodes / attributes; the
            // BodyRaw fallback below keeps detection on the raw bytes
            // in that case too.
            out.push(Extracted {
                source: StringSource::BodyRaw,
                bytes: Cow::Borrowed(body),
            });
            return out;
        }

        out.push(Extracted {
            source: StringSource::BodyRaw,
            bytes: Cow::Borrowed(body),
        });
        out
    }
}

fn is_json_content_type(ct: Option<&str>) -> bool {
    match ct {
        Some(s) => {
            let lower = s.to_ascii_lowercase();
            let mime = lower.split(';').next().unwrap_or("").trim();
            mime == "application/json" || mime.ends_with("+json") || mime == "text/json"
        }
        None => false,
    }
}

/// `application/x-www-form-urlencoded`, optionally with a `; charset=`
/// suffix. Matched case-insensitively.
fn is_form_urlencoded(ct: Option<&str>) -> bool {
    match ct {
        Some(s) => {
            let mime = s
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            mime == "application/x-www-form-urlencoded"
        }
        None => false,
    }
}

/// Extract the `boundary=…` parameter from a `multipart/*` content
/// type. Quoted (`boundary="x"`) and unquoted forms are both accepted.
fn multipart_boundary(ct: Option<&str>) -> Option<String> {
    let s = ct?;
    let lower = s.to_ascii_lowercase();
    let mut parts = lower.split(';');
    let mime = parts.next()?.trim();
    if !mime.starts_with("multipart/") {
        return None;
    }
    for part in s.split(';').skip(1) {
        let pair = part.trim();
        let Some(eq) = pair.find('=') else { continue };
        let (k, raw_v) = pair.split_at(eq);
        if k.trim().eq_ignore_ascii_case("boundary") {
            let v = raw_v[1..].trim();
            let v = v.trim_matches('"');
            if v.is_empty() {
                return None;
            }
            return Some(v.to_string());
        }
    }
    None
}

fn is_xml_content_type(ct: Option<&str>) -> bool {
    match ct {
        Some(s) => {
            let mime = s
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            mime == "application/xml"
                || mime == "text/xml"
                || mime.ends_with("+xml")
                || mime == "application/soap+xml"
        }
        None => false,
    }
}

/// Walk an `application/x-www-form-urlencoded` body. Emits one
/// [`StringSource::FormKey`] per key and one [`StringSource::FormValue`]
/// per value, all percent-decoded so a `%41%4B%49%41…` exfil channel
/// is normalised before reaching the regex.
///
/// Capped at [`MAX_FORM_FIELDS`] — pathological bodies with millions
/// of empty `&` separators don't get to allocate millions of
/// `Extracted` entries.
fn walk_form_urlencoded<'a>(body: &'a [u8], out: &mut Vec<Extracted<'a>>) {
    const MAX_FORM_FIELDS: usize = 4096;
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    let mut emitted = 0usize;
    for pair in text.split('&') {
        if emitted >= MAX_FORM_FIELDS {
            break;
        }
        if pair.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = match pair.find('=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, ""),
        };
        let key_bytes: Vec<u8> = percent_encoding::percent_decode_str(raw_k).collect();
        let val_bytes: Vec<u8> = percent_encoding::percent_decode_str(raw_v).collect();
        // Form-urlencoded encodes spaces as `+`. Convert before
        // emitting so the scanner doesn't have to special-case it.
        let val_bytes = val_bytes
            .into_iter()
            .map(|b| if b == b'+' { b' ' } else { b })
            .collect::<Vec<u8>>();
        let key_str = String::from_utf8_lossy(&key_bytes).into_owned();
        out.push(Extracted {
            source: StringSource::FormKey,
            bytes: Cow::Owned(key_bytes),
        });
        out.push(Extracted {
            source: StringSource::FormValue { key: key_str },
            bytes: Cow::Owned(val_bytes),
        });
        emitted += 1;
    }
}

/// Walk a `multipart/*` body. Splits on `--<boundary>` markers, finds
/// the `Content-Disposition: form-data; name="..."` of each part, and
/// emits the part body as [`StringSource::Multipart`].
///
/// Deliberately minimal: doesn't decode nested multipart, doesn't
/// follow `Content-Type` per-part for further structured walking.
/// Detection is preserved because every part's body is also covered
/// by the appended `BodyRaw` extraction at the call site.
///
/// Hard-capped at [`MAX_MULTIPART_PARTS`] to prevent DoS via a body
/// of all-boundaries.
fn walk_multipart<'a>(body: &'a [u8], boundary: &str, out: &mut Vec<Extracted<'a>>) {
    const MAX_MULTIPART_PARTS: usize = 256;
    let delim = format!("--{boundary}");
    let delim_bytes = delim.as_bytes();
    let mut parts = 0usize;
    let mut idx = 0usize;
    while idx + delim_bytes.len() <= body.len() && parts < MAX_MULTIPART_PARTS {
        // Find the next boundary.
        let Some(found) = find_subslice(&body[idx..], delim_bytes) else {
            break;
        };
        let after = idx + found + delim_bytes.len();
        // Skip CRLF (or LF) after the boundary marker.
        let part_start = match body.get(after) {
            Some(b'\r') if body.get(after + 1) == Some(&b'\n') => after + 2,
            Some(b'\n') => after + 1,
            // "--" terminator after the last boundary.
            Some(b'-') if body.get(after + 1) == Some(&b'-') => break,
            _ => after,
        };
        // Find the next boundary to bound this part.
        let part_end_search = part_start;
        let Some(next_off) = find_subslice(&body[part_end_search..], delim_bytes) else {
            break;
        };
        // Strip the trailing CRLF that precedes the next boundary.
        let part_end_raw = part_end_search + next_off;
        let part_end = part_end_raw.saturating_sub(
            if body.get(part_end_raw.wrapping_sub(2)) == Some(&b'\r') {
                2
            } else if body.get(part_end_raw.wrapping_sub(1)) == Some(&b'\n') {
                1
            } else {
                0
            },
        );

        let part = &body[part_start..part_end];
        // Split on the first empty line (`\r\n\r\n`) into headers / body.
        let (part_headers, part_body) = match find_subslice(part, b"\r\n\r\n") {
            Some(i) => (&part[..i], &part[i + 4..]),
            None => match find_subslice(part, b"\n\n") {
                Some(i) => (&part[..i], &part[i + 2..]),
                None => (b"".as_slice(), part),
            },
        };
        let name = parse_disposition_name(part_headers).unwrap_or_else(|| format!("part{parts}"));
        out.push(Extracted {
            source: StringSource::Multipart { field: name },
            bytes: Cow::Borrowed(part_body),
        });
        idx = part_end_raw;
        parts += 1;
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract the `name="…"` parameter from a part's Content-Disposition
/// header. Tolerates leading whitespace, single or double quotes,
/// and the case-insensitive header name.
fn parse_disposition_name(headers: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.split('\n') {
        let trimmed = line.trim_end_matches('\r');
        let Some(colon) = trimmed.find(':') else {
            continue;
        };
        let (h, v) = trimmed.split_at(colon);
        if !h.eq_ignore_ascii_case("content-disposition") {
            continue;
        }
        for param in v[1..].split(';') {
            let p = param.trim();
            let Some(eq) = p.find('=') else { continue };
            let (k, raw_v) = p.split_at(eq);
            if k.trim().eq_ignore_ascii_case("name") {
                let mut val = raw_v[1..].trim().to_string();
                if (val.starts_with('"') && val.ends_with('"'))
                    || (val.starts_with('\'') && val.ends_with('\''))
                {
                    val = val[1..val.len() - 1].to_string();
                }
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// Walk an XML body. Deliberately *not* a real XML parser: it scans
/// the byte stream for `>...<` text nodes and `attr="..."` /
/// `attr='...'` attribute values, tracking element nesting for path
/// attribution. Doesn't try to handle entities, CDATA, comments, or
/// processing instructions — those still get scanned via the
/// appended `BodyRaw` extraction. Detection is preserved; the walker
/// just improves attribution where it can.
///
/// Capped at [`MAX_XML_ELEMENTS`] to bound work on a hostile input.
fn walk_xml<'a>(body: &'a [u8], out: &mut Vec<Extracted<'a>>) {
    const MAX_XML_ELEMENTS: usize = 4096;
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    let bytes = text.as_bytes();
    let mut stack: Vec<String> = Vec::new();
    let mut elements_seen = 0usize;
    let mut i = 0usize;
    while i < bytes.len() && elements_seen < MAX_XML_ELEMENTS {
        match bytes[i] {
            b'<' => {
                // Tag start.
                if let Some(close) = find_subslice(&bytes[i + 1..], b">") {
                    let tag_end = i + 1 + close;
                    let tag_src = &text[i + 1..tag_end];
                    let is_close = tag_src.starts_with('/');
                    let is_self_close = tag_src.ends_with('/');
                    let body_src = tag_src.trim_start_matches('/').trim_end_matches('/').trim();
                    // First token is the element name.
                    let name_end = body_src
                        .find(|c: char| c.is_whitespace())
                        .unwrap_or(body_src.len());
                    let name = body_src[..name_end].to_string();
                    if name.is_empty() || name.starts_with('!') || name.starts_with('?') {
                        // Comment, doctype, or processing instruction —
                        // skip without touching the stack.
                        i = tag_end + 1;
                        continue;
                    }
                    if is_close {
                        if stack.last().is_some_and(|s| s == &name) {
                            stack.pop();
                        }
                    } else {
                        // Walk attributes.
                        let attrs_src = body_src[name_end..].trim();
                        let path = if stack.is_empty() {
                            name.clone()
                        } else {
                            format!("{}/{}", stack.join("/"), name)
                        };
                        emit_xml_attrs(attrs_src, &path, out);
                        if !is_self_close {
                            stack.push(name);
                        }
                    }
                    elements_seen += 1;
                    i = tag_end + 1;
                    continue;
                } else {
                    break;
                }
            }
            _ => {
                // Text node: read until the next `<`.
                let start = i;
                while i < bytes.len() && bytes[i] != b'<' {
                    i += 1;
                }
                let raw = &text[start..i];
                let trimmed = raw.trim();
                if !trimmed.is_empty() && !stack.is_empty() {
                    let path = stack.join("/");
                    out.push(Extracted {
                        source: StringSource::XmlText { path },
                        bytes: Cow::Owned(trimmed.as_bytes().to_vec()),
                    });
                }
            }
        }
    }
}

fn emit_xml_attrs<'a>(attrs_src: &str, path: &str, out: &mut Vec<Extracted<'a>>) {
    // Minimal `name="value"` / `name='value'` scanner. Doesn't decode
    // entities (`&amp;` stays as `&amp;`), but credentials don't
    // contain `&`, so this is fine for detection.
    let bytes = attrs_src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || name_start == i {
            break;
        }
        let name = std::str::from_utf8(&bytes[name_start..i])
            .unwrap_or("")
            .to_string();
        while i < bytes.len() && (bytes[i] == b'=' || bytes[i].is_ascii_whitespace()) {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let quote = bytes[i];
        if quote != b'"' && quote != b'\'' {
            // Unquoted attribute value — read until whitespace.
            let v_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let v = &attrs_src[v_start..i];
            if !v.is_empty() && !name.is_empty() {
                out.push(Extracted {
                    source: StringSource::XmlAttribute {
                        path: path.to_string(),
                        name,
                    },
                    bytes: Cow::Owned(v.as_bytes().to_vec()),
                });
            }
            continue;
        }
        i += 1; // skip opening quote
        let v_start = i;
        while i < bytes.len() && bytes[i] != quote {
            i += 1;
        }
        let v = &attrs_src[v_start..i];
        if i < bytes.len() {
            i += 1; // skip closing quote
        }
        if !name.is_empty() {
            out.push(Extracted {
                source: StringSource::XmlAttribute {
                    path: path.to_string(),
                    name,
                },
                bytes: Cow::Owned(v.as_bytes().to_vec()),
            });
        }
    }
}

fn walk_json_value<'a>(value: &serde_json::Value, path: String, out: &mut Vec<Extracted<'a>>) {
    match value {
        serde_json::Value::String(s) => {
            out.push(Extracted {
                source: StringSource::JsonString { path: path.clone() },
                bytes: Cow::Owned(s.clone().into_bytes()),
            });
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                let child = if path.is_empty() {
                    format!("[{i}]")
                } else {
                    format!("{path}[{i}]")
                };
                walk_json_value(item, child, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                // Keys can carry payload too — fuzzer's `json_key`
                // channel. Emit once per key.
                let key_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                out.push(Extracted {
                    source: StringSource::JsonKey {
                        path: key_path.clone(),
                    },
                    bytes: Cow::Owned(k.clone().into_bytes()),
                });
                walk_json_value(v, key_path, out);
            }
        }
        // Numbers / bools / null don't contain credential strings.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s<'a>(v: &'a Extracted<'a>) -> &'a str {
        std::str::from_utf8(&v.bytes).unwrap()
    }

    #[test]
    fn header_extract_emits_every_header_including_protocol_ones() {
        // Earlier revisions skipped "protocol" headers (Host,
        // User-Agent, Cookie, Referer, …). That was wrong: those are
        // the headers an attacker fully controls and the most
        // plausible exfil channels. The extractor must hand every
        // header to the scanner.
        let e = Extractor::default();
        let hdrs = vec![
            ("Host".to_string(), "evil.com".to_string()),
            ("User-Agent".to_string(), "curl/8.0".to_string()),
            ("Cookie".to_string(), "s=AKIA...".to_string()),
            ("Referer".to_string(), "https://x.test/".to_string()),
            ("X-Api-Key".to_string(), "secret".to_string()),
        ];
        let out = e.extract_headers(&hdrs);
        // 5 names + 5 values.
        assert_eq!(out.len(), 10);
        let labels: Vec<_> = out.iter().map(|x| x.source.label().into_owned()).collect();
        for must_have in [
            "header:Host",
            "header:User-Agent",
            "header:Cookie",
            "header:Referer",
            "header:X-Api-Key",
        ] {
            assert!(
                labels.iter().any(|l| l == must_have),
                "missing extraction for {must_have}; got {labels:?}"
            );
        }
    }

    #[test]
    fn header_names_can_be_disabled() {
        let e = Extractor {
            include_header_names: false,
            ..Default::default()
        };
        let hdrs = vec![("X-Custom".to_string(), "value".to_string())];
        let out = e.extract_headers(&hdrs);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].source, StringSource::HeaderValue { .. }));
    }

    #[test]
    fn uri_extract_splits_path_and_query() {
        let e = Extractor::default();
        let out = e.extract_uri("https://evil.com/leak/foo?token=AKIA&extra=bar");
        // 2 path segments + 2 query keys + 2 query values + 1 BodyRaw
        // fallback = 7
        assert_eq!(out.len(), 7);
        let paths: Vec<_> = out
            .iter()
            .filter_map(|x| match &x.source {
                StringSource::UriPath { segment_idx } => Some((*segment_idx, s(x).to_string())),
                _ => None,
            })
            .collect();
        assert_eq!(paths, vec![(0, "leak".to_string()), (1, "foo".to_string())]);
        let qvals: Vec<_> = out
            .iter()
            .filter_map(|x| match &x.source {
                StringSource::UriQueryValue { key } => Some((key.clone(), s(x).to_string())),
                _ => None,
            })
            .collect();
        assert!(qvals.contains(&("token".to_string(), "AKIA".to_string())));
        assert!(qvals.contains(&("extra".to_string(), "bar".to_string())));
    }

    #[test]
    fn uri_extract_handles_origin_form() {
        // No scheme/authority — origin-form like `GET /path HTTP/1.1`.
        let e = Extractor::default();
        let out = e.extract_uri("/leak/AKIA0123456789ABCDEF?q=v");
        assert!(
            out.iter()
                .any(|x| matches!(&x.source, StringSource::UriPath { segment_idx: 1 }))
        );
        assert!(out.iter().any(|x| matches!(
            &x.source,
            StringSource::UriQueryValue { key } if key == "q"
        )));
    }

    #[test]
    fn uri_extract_percent_decodes_segments() {
        let e = Extractor::default();
        let out = e.extract_uri("/a/%41%4B%49%41/b");
        let seg = out
            .iter()
            .find_map(|x| match &x.source {
                StringSource::UriPath { segment_idx: 1 } => Some(s(x).to_string()),
                _ => None,
            })
            .unwrap();
        assert_eq!(seg, "AKIA");
    }

    #[test]
    fn json_walk_emits_string_paths() {
        let e = Extractor::default();
        let body = br#"{"user":{"tokens":["AKIA0123456789ABCDEF","other"]}}"#;
        let out = e.extract_body(body, Some("application/json"));
        let json_paths: Vec<_> = out
            .iter()
            .filter_map(|x| match &x.source {
                StringSource::JsonString { path } => Some((path.clone(), s(x).to_string())),
                _ => None,
            })
            .collect();
        assert!(
            json_paths
                .iter()
                .any(|(p, v)| p == "user.tokens[0]" && v == "AKIA0123456789ABCDEF")
        );
        assert!(
            json_paths
                .iter()
                .any(|(p, v)| p == "user.tokens[1]" && v == "other")
        );
    }

    #[test]
    fn json_walk_emits_keys() {
        let e = Extractor::default();
        let body = br#"{"AKIA0123456789ABCDEF":"v"}"#;
        let out = e.extract_body(body, Some("application/json"));
        let keys: Vec<_> = out
            .iter()
            .filter_map(|x| match &x.source {
                StringSource::JsonKey { path } => Some((path.clone(), s(x).to_string())),
                _ => None,
            })
            .collect();
        assert!(
            keys.iter()
                .any(|(p, v)| p == "AKIA0123456789ABCDEF" && v == "AKIA0123456789ABCDEF")
        );
    }

    #[test]
    fn json_parse_failure_falls_back_to_body_raw() {
        let e = Extractor::default();
        let body = b"{not valid json";
        let out = e.extract_body(body, Some("application/json"));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].source, StringSource::BodyRaw));
    }

    #[test]
    fn json_oversize_body_falls_back_to_body_raw() {
        let e = Extractor {
            max_json_parse_bytes: 16,
            ..Default::default()
        };
        let body = br#"{"k":"AKIA0123456789ABCDEF"}"#; // > 16 bytes
        let out = e.extract_body(body, Some("application/json"));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].source, StringSource::BodyRaw));
    }

    #[test]
    fn non_json_content_type_is_opaque() {
        let e = Extractor::default();
        let body = br#"{"k":"v"}"#;
        let out = e.extract_body(body, Some("application/octet-stream"));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0].source, StringSource::BodyRaw));
    }

    #[test]
    fn json_content_type_with_charset_parses() {
        let e = Extractor::default();
        let body = br#"{"k":"v"}"#;
        let out = e.extract_body(body, Some("application/json; charset=utf-8"));
        assert!(
            out.iter()
                .any(|x| matches!(x.source, StringSource::JsonString { .. }))
        );
    }

    #[test]
    fn json_plus_suffix_content_type_parses() {
        let e = Extractor::default();
        let body = br#"{"k":"v"}"#;
        let out = e.extract_body(body, Some("application/vnd.api+json"));
        assert!(
            out.iter()
                .any(|x| matches!(x.source, StringSource::JsonString { .. }))
        );
    }

    #[test]
    fn string_source_label_format() {
        assert_eq!(StringSource::HeaderName.label(), "header_name");
        assert_eq!(
            StringSource::HeaderValue {
                name: "X-Foo".into()
            }
            .label(),
            "header:X-Foo"
        );
        assert_eq!(
            StringSource::JsonString {
                path: "a.b[0]".into()
            }
            .label(),
            "json:a.b[0]"
        );
        assert_eq!(StringSource::TrailerName.label(), "trailer_name");
        assert_eq!(
            StringSource::TrailerValue {
                name: "X-Sig".into()
            }
            .label(),
            "trailer:X-Sig"
        );
        assert_eq!(
            StringSource::FormValue {
                key: "token".into()
            }
            .label(),
            "form:token"
        );
        assert_eq!(
            StringSource::XmlText {
                path: "soap:Envelope/soap:Body/Auth".into()
            }
            .label(),
            "xml:soap:Envelope/soap:Body/Auth"
        );
        assert_eq!(
            StringSource::XmlAttribute {
                path: "Cfg".into(),
                name: "key".into(),
            }
            .label(),
            "xml:Cfg@key"
        );
    }

    // =================================================================
    // Trailer extraction
    // =================================================================

    #[test]
    fn trailer_extract_emits_every_trailer() {
        let e = Extractor::default();
        let tr = vec![
            ("X-Sig".to_string(), "AKIA...".to_string()),
            ("X-Checksum".to_string(), "sha256=…".to_string()),
        ];
        let out = e.extract_trailers(&tr);
        assert_eq!(out.len(), 4);
        let labels: Vec<_> = out.iter().map(|x| x.source.label().into_owned()).collect();
        assert!(labels.iter().any(|l| l == "trailer:X-Sig"));
        assert!(labels.iter().any(|l| l == "trailer:X-Checksum"));
        assert!(labels.iter().filter(|l| l == &"trailer_name").count() == 2);
    }

    // =================================================================
    // Form-urlencoded walker
    // =================================================================

    #[test]
    fn form_urlencoded_walker_splits_and_decodes() {
        let e = Extractor::default();
        let body = b"name=alice&token=ghp_secret&other=value";
        let out = e.extract_body(body, Some("application/x-www-form-urlencoded"));
        let labels: Vec<_> = out.iter().map(|x| x.source.label().into_owned()).collect();
        assert!(labels.iter().any(|l| l == "form:token"));
        // Extracted value bytes for the `token` key carry only the
        // value, not the key.
        let tok = out
            .iter()
            .find(|x| matches!(&x.source, StringSource::FormValue { key } if key == "token"))
            .unwrap();
        assert_eq!(s(tok), "ghp_secret");
    }

    #[test]
    fn form_urlencoded_walker_percent_decodes_value() {
        let e = Extractor::default();
        // %41%4B%49%41 is "AKIA" — percent-decoded once on extraction
        // so the scanner doesn't have to undo it later.
        let body = b"key=%41%4B%49%41%31%32%33%34%35%36%37%38%39%30%41%42%43%44%45%46";
        let out = e.extract_body(body, Some("application/x-www-form-urlencoded"));
        let v = out
            .iter()
            .find(|x| matches!(&x.source, StringSource::FormValue { key } if key == "key"))
            .unwrap();
        assert_eq!(s(v), "AKIA1234567890ABCDEF");
    }

    #[test]
    fn form_urlencoded_walker_handles_plus_as_space() {
        let e = Extractor::default();
        let body = b"k=hello+world";
        let out = e.extract_body(body, Some("application/x-www-form-urlencoded"));
        let v = out
            .iter()
            .find(|x| matches!(&x.source, StringSource::FormValue { key } if key == "k"))
            .unwrap();
        assert_eq!(s(v), "hello world");
    }

    // =================================================================
    // Multipart walker
    // =================================================================

    #[test]
    fn multipart_walker_extracts_each_part_with_name() {
        let e = Extractor::default();
        let body: &[u8] = b"--boundary42\r\n\
            Content-Disposition: form-data; name=\"username\"\r\n\
            \r\n\
            alice\r\n\
            --boundary42\r\n\
            Content-Disposition: form-data; name=\"token\"\r\n\
            \r\n\
            AKIA1234567890ABCDEF\r\n\
            --boundary42--\r\n";
        let out = e.extract_body(body, Some("multipart/form-data; boundary=boundary42"));
        let labels: Vec<_> = out.iter().map(|x| x.source.label().into_owned()).collect();
        assert!(labels.iter().any(|l| l == "multipart:username"));
        assert!(labels.iter().any(|l| l == "multipart:token"));
        let tok = out
            .iter()
            .find(|x| matches!(&x.source, StringSource::Multipart { field } if field == "token"))
            .unwrap();
        assert_eq!(s(tok), "AKIA1234567890ABCDEF");
    }

    #[test]
    fn multipart_walker_tolerates_unquoted_boundary() {
        let e = Extractor::default();
        let body: &[u8] = b"--xyz\r\n\
            Content-Disposition: form-data; name=\"k\"\r\n\
            \r\n\
            v\r\n\
            --xyz--\r\n";
        // boundary without quotes.
        let out = e.extract_body(body, Some("multipart/form-data; boundary=xyz"));
        assert!(
            out.iter()
                .any(|x| matches!(&x.source, StringSource::Multipart { field } if field == "k"))
        );
    }

    #[test]
    fn multipart_walker_falls_back_to_part_n_when_name_missing() {
        let e = Extractor::default();
        let body: &[u8] = b"--b\r\n\
            \r\n\
            ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\
            --b--\r\n";
        let out = e.extract_body(body, Some("multipart/form-data; boundary=b"));
        assert!(
            out.iter().any(
                |x| matches!(&x.source, StringSource::Multipart { field } if field == "part0")
            )
        );
    }

    // =================================================================
    // XML walker
    // =================================================================

    #[test]
    fn xml_walker_extracts_text_with_path() {
        let e = Extractor::default();
        let body =
            b"<root><Auth><Token>ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</Token></Auth></root>";
        let out = e.extract_body(body, Some("application/xml"));
        let labels: Vec<_> = out.iter().map(|x| x.source.label().into_owned()).collect();
        assert!(labels.iter().any(|l| l == "xml:root/Auth/Token"));
    }

    #[test]
    fn xml_walker_extracts_attribute_values() {
        let e = Extractor::default();
        let body = b"<Cfg token=\"AKIA1234567890ABCDEF\" name='public'/>";
        let out = e.extract_body(body, Some("application/xml"));
        let labels: Vec<_> = out.iter().map(|x| x.source.label().into_owned()).collect();
        assert!(labels.iter().any(|l| l == "xml:Cfg@token"));
        let tok = out
            .iter()
            .find(
                |x| matches!(&x.source, StringSource::XmlAttribute { name, .. } if name == "token"),
            )
            .unwrap();
        assert_eq!(s(tok), "AKIA1234567890ABCDEF");
    }

    #[test]
    fn xml_walker_skips_comments_doctype_pi() {
        let e = Extractor::default();
        let body = b"<?xml version=\"1.0\"?><!DOCTYPE r><!--comment--><r><x>v</x></r>";
        // No panic; xml:r/x text node present.
        let out = e.extract_body(body, Some("text/xml"));
        assert!(
            out.iter()
                .any(|x| matches!(&x.source, StringSource::XmlText { path } if path == "r/x"))
        );
    }

    #[test]
    fn xml_walker_recognises_soap_and_plus_xml() {
        let e = Extractor::default();
        // application/soap+xml is the SOAP 1.2 content type.
        let body = b"<s:Envelope xmlns:s=\"x\"><s:Body><Tok>ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</Tok></s:Body></s:Envelope>";
        let out = e.extract_body(body, Some("application/soap+xml; charset=utf-8"));
        assert!(
            out.iter().any(
                |x| matches!(&x.source, StringSource::XmlText { path } if path.ends_with("Tok"))
            )
        );
    }
}
