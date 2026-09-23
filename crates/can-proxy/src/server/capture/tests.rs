//! Unit tests for exchange capture. In their own file so the
//! production-path unwrap guard skips them wholesale.

use super::*;
use base64::Engine;
use hyper::header::{HeaderName, HeaderValue};

fn ctx_with_secrets(secrets: &[&str]) -> CaptureCtx {
    let mut values: Vec<String> = secrets.iter().map(|s| s.to_string()).collect();
    values.sort_by_key(|value| std::cmp::Reverse(value.len()));
    CaptureCtx {
        max_bytes: 1024,
        secrets: Arc::new(values),
    }
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_str(value).expect("header value"),
        );
    }
    map
}

fn decode(body: &CapturedBody) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(body.base64.as_deref().expect("body"))
        .expect("valid base64")
}

#[test]
fn credential_headers_are_always_redacted() {
    let ctx = ctx_with_secrets(&[]);
    let captured = ctx.headers(&headers(&[
        ("authorization", "Bearer sk-live-123"),
        ("x-api-key", "key-abc"),
        ("api-key", "key-abc"),
        ("cookie", "session=1"),
        ("proxy-authorization", "Basic zzz"),
        ("content-type", "application/json"),
    ]));

    for (name, value) in &captured {
        if name == "content-type" {
            assert_eq!(value, "application/json");
        } else {
            assert_eq!(value, "[redacted]", "header {name} must be redacted");
        }
    }
}

#[test]
fn secret_values_are_removed_from_any_header() {
    let ctx = ctx_with_secrets(&["fake-token-value", "real-token-value"]);
    let captured = ctx.headers(&headers(&[
        ("x-custom-auth", "prefix real-token-value suffix"),
        ("x-echo", "fake-token-value"),
    ]));

    let rendered = format!("{captured:?}");
    assert!(!rendered.contains("real-token-value"));
    assert!(!rendered.contains("fake-token-value"));
    assert!(rendered.contains("prefix [redacted] suffix"));
}

#[test]
fn secret_values_are_removed_from_bodies_including_binary_ones() {
    let ctx = ctx_with_secrets(&["real-token-value"]);
    let mut body = vec![0x00, 0xff, 0x10];
    body.extend_from_slice(b"real-token-value");
    body.extend_from_slice(&[0x00, 0xfe]);

    let captured = ctx.body(&body);
    let decoded = decode(&captured);

    assert!(
        !decoded
            .windows(b"real-token-value".len())
            .any(|w| w == b"real-token-value"),
        "the real secret must not survive capture"
    );
    assert!(
        decoded
            .windows(b"[redacted]".len())
            .any(|w| w == b"[redacted]")
    );
    assert_eq!(captured.body_bytes, body.len());
    assert!(!captured.truncated);
}

#[test]
fn a_secret_in_the_url_is_removed() {
    let ctx = ctx_with_secrets(&["real-token-value"]);
    let url = ctx.url("https://api.example.com/v1?token=real-token-value&x=1");

    assert_eq!(url, "https://api.example.com/v1?token=[redacted]&x=1");
}

#[test]
fn bodies_over_the_cap_are_truncated_and_flagged() {
    let ctx = CaptureCtx {
        max_bytes: 8,
        secrets: Arc::new(Vec::new()),
    };
    let body = vec![b'a'; 100];

    let captured = ctx.body(&body);

    assert!(captured.truncated);
    assert_eq!(captured.body_bytes, 100, "pre-truncation size is reported");
    assert_eq!(decode(&captured).len(), 8);
}

#[test]
fn a_body_exactly_at_the_cap_is_not_truncated() {
    let ctx = CaptureCtx {
        max_bytes: 8,
        secrets: Arc::new(Vec::new()),
    };

    let captured = ctx.body(&[b'a'; 8]);

    assert!(!captured.truncated);
    assert_eq!(decode(&captured).len(), 8);
}

#[test]
fn one_byte_over_the_cap_is_truncated() {
    let ctx = CaptureCtx {
        max_bytes: 8,
        secrets: Arc::new(Vec::new()),
    };

    let captured = ctx.body(&[b'a'; 9]);

    assert!(captured.truncated);
    assert_eq!(decode(&captured).len(), 8);
}

#[test]
fn overlapping_secrets_are_replaced_longest_first() {
    // A fake and a real value that share a prefix must not leave a
    // fragment of the longer one behind.
    let ctx = ctx_with_secrets(&["tok-abc", "tok-abc-extended"]);

    let captured = ctx.body(b"value=tok-abc-extended");
    let decoded = String::from_utf8(decode(&captured)).expect("utf8");

    assert_eq!(decoded, "value=[redacted]");
}

#[test]
fn a_non_utf8_header_value_is_redacted_rather_than_guessed() {
    let ctx = ctx_with_secrets(&[]);
    let mut map = HeaderMap::new();
    map.insert(
        HeaderName::from_static("x-binary"),
        HeaderValue::from_bytes(&[0xff, 0xfe]).expect("header value"),
    );

    let captured = ctx.headers(&map);

    assert_eq!(captured[0].1, "[redacted]");
}

#[test]
fn an_exchange_without_a_recorded_request_emits_nothing() {
    // No stream is installed in unit tests, so this asserts the guard
    // rather than the emission: the recorder must not panic or block.
    let recorder = ExchangeRecorder::new(ctx_with_secrets(&[]), "api.example.com");
    recorder.emit();
}

#[test]
fn replace_all_handles_needles_longer_than_the_haystack() {
    assert_eq!(replace_all(b"ab", b"abcdef", b"x"), b"ab".to_vec());
    assert_eq!(replace_all(b"abc", b"", b"x"), b"abc".to_vec());
    assert_eq!(replace_all(b"aaa", b"a", b"bb"), b"bbbbbb".to_vec());
}
