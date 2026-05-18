/// Decode JSON-style string escapes (`\n`, `\"`, `\uXXXX`, surrogate pairs)
/// and HTML named/numeric entities back to literal characters. Returns the
/// input unchanged if no escape sequence is present.
///
/// This is the second normalisation pass: F5 in the DLP plan. Without it, a
/// JSON body like `{"token":"ghp_A…"}` slips past the regex set because
/// the literal bytes seen by the scanner are `A`, not the decoded `A`.
pub fn unescape(input: &str) -> String {
    if !needs_unescape(input) {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('u') => {
                    if let Some(decoded) = take_unicode_escape(&mut chars) {
                        out.push(decoded);
                    } else {
                        out.push('\\');
                        out.push('u');
                    }
                }
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\u{0008}'),
                Some('f') => out.push('\u{000C}'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some('/') => out.push('/'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            },
            '&' => match take_html_entity(&mut chars) {
                EntityResult::Decoded(s) => out.push_str(&s),
                EntityResult::NotAnEntity(consumed) => {
                    out.push('&');
                    out.push_str(&consumed);
                }
            },
            other => out.push(other),
        }
    }
    out
}

fn needs_unescape(s: &str) -> bool {
    let bytes = s.as_bytes();
    // Quick reject: only scan strings that contain at least one trigger byte.
    bytes.iter().any(|&b| b == b'\\' || b == b'&')
}

fn take_unicode_escape(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<char> {
    let hex: String = (0..4).map(|_| chars.next()).collect::<Option<String>>()?;
    if hex.len() != 4 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let code = u32::from_str_radix(&hex, 16).ok()?;

    // Handle UTF-16 surrogate pairs: JSON encodes characters above U+FFFF as
    // `😀`-style pairs. We need to peek for the trailing `\uXXXX`.
    if (0xD800..=0xDBFF).contains(&code) {
        // High surrogate — try to consume a matching low surrogate.
        if let (Some(&'\\'), _) = (chars.peek(), ()) {
            let _ = chars.next(); // '\\'
            if chars.next() == Some('u') {
                let low_hex: String = (0..4).map(|_| chars.next()).collect::<Option<String>>()?;
                if let Ok(low) = u32::from_str_radix(&low_hex, 16) {
                    if (0xDC00..=0xDFFF).contains(&low) {
                        let combined = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                        return char::from_u32(combined);
                    }
                }
                return None;
            }
        }
        return None;
    }
    char::from_u32(code)
}

enum EntityResult {
    /// Entity decoded successfully — chars consumed up to and including `;`.
    Decoded(String),
    /// Not an entity. The string contains the chars we consumed past `&`
    /// (excluding `&` itself); the caller re-emits `&` + this prefix.
    NotAnEntity(String),
}

fn take_html_entity(chars: &mut std::iter::Peekable<std::str::Chars>) -> EntityResult {
    // Bounded scan — entities are short. Anything longer than ~10 body
    // chars without a closing `;` is treated as a literal `&` and the
    // consumed prefix is returned to the caller so we don't lose data.
    let mut buf = String::new();
    for _ in 0..12 {
        match chars.peek() {
            Some(&';') => {
                let _ = chars.next();
                return match decode_entity(&buf) {
                    Some(decoded) => EntityResult::Decoded(decoded),
                    // Unknown entity (e.g. `&foo;`): the `;` is consumed,
                    // so the caller must re-emit `&{body};` verbatim.
                    None => EntityResult::NotAnEntity(format!("{buf};")),
                };
            }
            Some(&c) if c.is_ascii_alphanumeric() || c == '#' || c == 'x' || c == 'X' => {
                buf.push(c);
                let _ = chars.next();
            }
            _ => return EntityResult::NotAnEntity(buf),
        }
    }
    EntityResult::NotAnEntity(buf)
}

fn decode_entity(body: &str) -> Option<String> {
    if let Some(rest) = body.strip_prefix('#') {
        let code = if let Some(hex) = rest.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            rest.parse::<u32>().ok()?
        };
        return char::from_u32(code).map(|c| c.to_string());
    }
    Some(
        match body {
            "amp" => "&",
            "lt" => "<",
            "gt" => ">",
            "quot" => "\"",
            "apos" => "'",
            "nbsp" => "\u{00A0}",
            _ => return None,
        }
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescape_plain_text_passthrough() {
        let input = "no escapes here";
        assert_eq!(unescape(input), input);
    }

    #[test]
    fn unescape_json_unicode_escape() {
        // A = 'A'. Encoding `ghp_A…` as `ghp_A…` is the
        // canonical evasion this pass defends against.
        let input = r"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let out = unescape(input);
        assert!(out.starts_with("ghp_AAAA"));
    }

    #[test]
    fn unescape_json_string_escapes() {
        assert_eq!(unescape(r"line1\nline2"), "line1\nline2");
        assert_eq!(unescape(r"tab\there"), "tab\there");
        assert_eq!(unescape(r#"quote: \""#), "quote: \"");
        assert_eq!(unescape(r"backslash: \\"), "backslash: \\");
    }

    #[test]
    fn unescape_surrogate_pair() {
        // 😀 = U+1F600, encoded as 😀.
        let input = r"emoji: 😀";
        assert_eq!(unescape(input), "emoji: 😀");
    }

    #[test]
    fn unescape_html_named_entities() {
        assert_eq!(unescape("a &amp; b"), "a & b");
        assert_eq!(unescape("&lt;tag&gt;"), "<tag>");
        assert_eq!(unescape("&quot;hi&quot;"), "\"hi\"");
    }

    #[test]
    fn unescape_html_numeric_entities() {
        // 'A' = 65 dec = 0x41 hex
        assert_eq!(unescape("&#65;"), "A");
        assert_eq!(unescape("&#x41;"), "A");
        assert_eq!(unescape("&#x68;&#x69;"), "hi");
    }

    #[test]
    fn unescape_token_via_html_entities() {
        // `ghp_` encoded as `&#103;hp_…` is a realistic CSV / HTML
        // injection vector.
        let input = "&#103;hp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let out = unescape(input);
        assert!(out.starts_with("ghp_"));
    }

    #[test]
    fn unescape_bad_unicode_kept_literal() {
        // Malformed `\u` (not 4 hex digits) is kept literally — the
        // scanner should not try to be clever and silently consume
        // partial sequences.
        let input = r"abc\uZZZZ";
        let out = unescape(input);
        assert!(out.contains("\\u"));
    }

    #[test]
    fn unescape_unknown_entity_kept_literal() {
        let input = "weird &foo; thing";
        // Unknown entity bodies are kept as-is.
        let out = unescape(input);
        assert!(out.contains("&foo"));
    }

    #[test]
    fn unescape_lone_ampersand_kept() {
        assert_eq!(unescape("Q&A"), "Q&A");
    }

    #[test]
    fn unescape_empty_input() {
        assert_eq!(unescape(""), "");
    }

    #[test]
    fn unescape_short_circuits_when_no_triggers() {
        // No backslash or ampersand → exactly the same string back.
        let input = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(unescape(input), input);
    }
}
