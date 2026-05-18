/// Expand environment variables in a string.
///
/// Supports two forms:
/// - `$NAME` — bare variable (terminated by non-alphanumeric, non-underscore)
/// - `${NAME}` — braced variable
///
/// Unknown or unset variables are replaced with an empty string.
/// Literal `$$` is escaped to a single `$`.
///
/// This is intentionally simple — no default values, no nested expansion.
/// Used for recipe paths like `$HOME/.cargo/bin`.
pub fn expand_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '$' {
            result.push(ch);
            continue;
        }

        // $$ → literal $
        if chars.peek() == Some(&'$') {
            chars.next();
            result.push('$');
            continue;
        }

        // ${NAME} — braced form
        if chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut name = String::new();
            for c in chars.by_ref() {
                if c == '}' {
                    break;
                }
                name.push(c);
            }
            if let Ok(val) = std::env::var(&name) {
                result.push_str(&val);
            }
            continue;
        }

        // $NAME — bare form (alphanumeric + underscore)
        let mut name = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                name.push(c);
                chars.next();
            } else {
                break;
            }
        }

        if name.is_empty() {
            // Lone $ at end of string or before non-identifier char
            result.push('$');
        } else if let Ok(val) = std::env::var(&name) {
            result.push_str(&val);
        }
        // Unset variables expand to empty string (no output).
    }

    result
}
