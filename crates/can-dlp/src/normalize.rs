/// Normalize a string by stripping zero-width characters, converting
/// homoglyphs to ASCII, removing combining marks (Zalgo text), and
/// normalizing exotic whitespace.
pub fn normalize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if is_zero_width(ch) {
            continue;
        }
        if is_combining_mark(ch) {
            continue;
        }
        if let Some(ascii) = homoglyph_to_ascii(ch) {
            out.push(ascii);
            continue;
        }
        if is_exotic_whitespace(ch) {
            out.push(' ');
            continue;
        }
        out.push(ch);
    }
    out
}

fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // ZERO WIDTH SPACE
        | '\u{200C}' // ZERO WIDTH NON-JOINER
        | '\u{200D}' // ZERO WIDTH JOINER
        | '\u{200E}' // LEFT-TO-RIGHT MARK
        | '\u{200F}' // RIGHT-TO-LEFT MARK
        | '\u{FEFF}' // BOM / ZERO WIDTH NO-BREAK SPACE
        | '\u{00AD}' // SOFT HYPHEN
        | '\u{2060}' // WORD JOINER
        | '\u{2061}' // FUNCTION APPLICATION
        | '\u{2062}' // INVISIBLE TIMES
        | '\u{2063}' // INVISIBLE SEPARATOR
        | '\u{2064}' // INVISIBLE PLUS
        | '\u{034F}' // COMBINING GRAPHEME JOINER
        | '\u{061C}' // ARABIC LETTER MARK
        | '\u{180E}' // MONGOLIAN VOWEL SEPARATOR
    )
}

fn is_combining_mark(ch: char) -> bool {
    let cp = ch as u32;
    // Combining Diacritical Marks (U+0300–U+036F)
    (0x0300..=0x036F).contains(&cp)
    // Combining Diacritical Marks Extended (U+1AB0–U+1AFF)
    || (0x1AB0..=0x1AFF).contains(&cp)
    // Combining Diacritical Marks Supplement (U+1DC0–U+1DFF)
    || (0x1DC0..=0x1DFF).contains(&cp)
    // Combining Half Marks (U+FE20–U+FE2F)
    || (0xFE20..=0xFE2F).contains(&cp)
    // Combining Diacritical Marks for Symbols (U+20D0–U+20FF)
    || (0x20D0..=0x20FF).contains(&cp)
}

fn is_exotic_whitespace(ch: char) -> bool {
    matches!(
        ch,
        '\u{00A0}' // NO-BREAK SPACE
        | '\u{1680}' // OGHAM SPACE MARK
        | '\u{2000}' // EN QUAD
        | '\u{2001}' // EM QUAD
        | '\u{2002}' // EN SPACE
        | '\u{2003}' // EM SPACE
        | '\u{2004}' // THREE-PER-EM SPACE
        | '\u{2005}' // FOUR-PER-EM SPACE
        | '\u{2006}' // SIX-PER-EM SPACE
        | '\u{2007}' // FIGURE SPACE
        | '\u{2008}' // PUNCTUATION SPACE
        | '\u{2009}' // THIN SPACE
        | '\u{200A}' // HAIR SPACE
        | '\u{202F}' // NARROW NO-BREAK SPACE
        | '\u{205F}' // MEDIUM MATHEMATICAL SPACE
        | '\u{3000}' // IDEOGRAPHIC SPACE
    )
}

/// Map visually confusable Unicode characters to their ASCII equivalents.
/// Covers Cyrillic, Greek, and fullwidth forms most commonly used in evasion.
fn homoglyph_to_ascii(ch: char) -> Option<char> {
    Some(match ch {
        // Cyrillic → Latin
        '\u{0430}' => 'a', // а
        '\u{0410}' => 'A', // А
        '\u{0435}' => 'e', // е
        '\u{0415}' => 'E', // Е
        '\u{043E}' => 'o', // о
        '\u{041E}' => 'O', // О
        '\u{0440}' => 'p', // р
        '\u{0420}' => 'P', // Р
        '\u{0441}' => 'c', // с
        '\u{0421}' => 'C', // С
        '\u{0443}' => 'y', // у
        '\u{0423}' => 'Y', // У (visual Y)
        '\u{0445}' => 'x', // х
        '\u{0425}' => 'X', // Х
        '\u{043A}' => 'k', // к (visual k)
        '\u{041A}' => 'K', // К
        '\u{043C}' => 'm', // м (visual m in some fonts)
        '\u{0422}' => 'T', // Т
        '\u{0442}' => 't', // т (visual t in some italic fonts)
        '\u{0456}' => 'i', // і (Ukrainian i)
        '\u{0406}' => 'I', // І
        '\u{0458}' => 'j', // ј (Serbian je)
        '\u{0408}' => 'J', // Ј
        '\u{0455}' => 's', // ѕ (Macedonian dze)
        '\u{0405}' => 'S', // Ѕ

        // Greek → Latin
        '\u{03B1}' => 'a', // α (sometimes confusable)
        '\u{0391}' => 'A', // Α
        '\u{0392}' => 'B', // Β
        '\u{03B5}' => 'e', // ε
        '\u{0395}' => 'E', // Ε
        '\u{0397}' => 'H', // Η
        '\u{0399}' => 'I', // Ι
        '\u{039A}' => 'K', // Κ
        '\u{039C}' => 'M', // Μ
        '\u{039D}' => 'N', // Ν
        '\u{039F}' => 'O', // Ο
        '\u{03BF}' => 'o', // ο
        '\u{03A1}' => 'P', // Ρ
        '\u{03C1}' => 'p', // ρ
        '\u{03A4}' => 'T', // Τ
        '\u{03A5}' => 'Y', // Υ
        '\u{03A7}' => 'X', // Χ
        '\u{03C7}' => 'x', // χ
        '\u{0396}' => 'Z', // Ζ

        // Fullwidth ASCII → normal ASCII (U+FF01–U+FF5E → U+0021–U+007E)
        '\u{FF01}'..='\u{FF5E}' => {
            let offset = ch as u32 - 0xFF01;
            char::from(0x21u8 + offset as u8)
        }

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_chars() {
        let input = "ghp_\u{200B}AAAA\u{200C}BBBB\u{200D}CCCC\u{FEFF}DDDD";
        assert_eq!(normalize(input), "ghp_AAAABBBBCCCCDDDD");
    }

    #[test]
    fn strips_soft_hyphen() {
        let input = "ghp_\u{00AD}SECRET";
        assert_eq!(normalize(input), "ghp_SECRET");
    }

    #[test]
    fn normalizes_cyrillic_homoglyphs() {
        // "ghр_" with Cyrillic р (U+0440) instead of Latin p
        let input = "gh\u{0440}_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let normalized = normalize(input);
        assert!(
            normalized.starts_with("ghp_"),
            "Cyrillic р should normalize to Latin p: {normalized}"
        );
    }

    #[test]
    fn normalizes_cyrillic_a_e_o() {
        let input = "\u{0430}\u{0435}\u{043E}"; // Cyrillic а, е, о
        assert_eq!(normalize(input), "aeo");
    }

    #[test]
    fn normalizes_greek_homoglyphs() {
        // Greek Ο (U+039F) and ο (U+03BF)
        let input = "\u{039F}pen\u{03BF}pen";
        assert_eq!(normalize(input), "Openopen");
    }

    #[test]
    fn strips_combining_marks_zalgo() {
        let input = "g\u{0300}h\u{0301}p\u{0302}_\u{0303}S\u{0304}E\u{0305}C";
        assert_eq!(normalize(input), "ghp_SEC");
    }

    #[test]
    fn normalizes_exotic_whitespace() {
        // NO-BREAK SPACE, EN SPACE, EM SPACE, THIN SPACE
        let input = "Bearer\u{00A0}token\u{2002}here\u{2009}now";
        assert_eq!(normalize(input), "Bearer token here now");
    }

    #[test]
    fn normalizes_fullwidth_ascii() {
        // ｇｈｐ＿ in fullwidth
        let input = "\u{FF47}\u{FF48}\u{FF50}\u{FF3F}SECRET";
        assert_eq!(normalize(input), "ghp_SECRET");
    }

    #[test]
    fn preserves_normal_ascii() {
        let input = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(normalize(input), input);
    }

    #[test]
    fn handles_empty_input() {
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn complex_evasion_attempt() {
        // Token with ZWC between every char + Cyrillic confusables
        let input = "gh\u{0440}\u{200B}_\u{200C}S\u{0300}E\u{0301}C\u{0302}R\u{0303}ET";
        let normalized = normalize(input);
        assert_eq!(normalized, "ghp_SECRET");
    }

    #[test]
    fn multiple_zwc_types_stripped() {
        let zwcs =
            "\u{200B}\u{200C}\u{200D}\u{200E}\u{200F}\u{FEFF}\u{00AD}\u{2060}\u{034F}\u{061C}";
        assert_eq!(normalize(zwcs), "");
    }

    #[test]
    fn fullwidth_digits() {
        let input = "\u{FF11}\u{FF12}\u{FF13}\u{FF14}"; // １２３４
        assert_eq!(normalize(input), "1234");
    }
}
