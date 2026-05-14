#!/usr/bin/env bash
# Guard against `.unwrap()`, `.expect(...)`, and `panic!(...)` in production
# paths under `crates/*/src`. Test code (`#[cfg(test)] mod tests { ... }`) is
# exempt, as are individual lines annotated with `// SAFETY-UNWRAP:` (or any
# `// SAFETY-` prefix) immediately preceding them, *or* on the same line.
#
# Exit codes:
#   0 — all unwraps are either in tests or annotated
#   1 — found unannotated unwrap/expect/panic! in production code
#
# This is intentionally simple (single awk pass per file). The goal is to
# prevent *new* unwraps from leaking in; existing ones can be allow-listed
# with a one-line comment.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

violations=0
report=""

for file in $(find crates -path '*/src/*.rs' -type f); do
    # awk script:
    #   - Skip everything from `#[cfg(test)]` (followed by `mod ... {`) until
    #     the matching closing brace. We track brace depth from the line that
    #     opens the test module.
    #   - Inside production code: flag lines containing .unwrap() / .expect( /
    #     panic!( unless they (or the previous line) carry a `// SAFETY-` tag.
    while IFS= read -r hit; do
        violations=$((violations + 1))
        report+="$hit"$'\n'
    done < <(awk '
        BEGIN { in_test = 0; depth = 0; safety_active = 0 }
        {
            if (in_test == 0 && $0 ~ /#\[cfg\(test\)\]/) {
                expect_test_mod = 1
                next
            }
            if (expect_test_mod && $0 ~ /mod [a-zA-Z_]+ *\{/) {
                in_test = 1
                expect_test_mod = 0
                # Count opening braces on this line (mod tests {).
                depth = gsub(/\{/, "{") - gsub(/\}/, "}")
                next
            }
            if (in_test) {
                depth += gsub(/\{/, "{") - gsub(/\}/, "}")
                if (depth <= 0) {
                    in_test = 0
                    depth = 0
                }
                next
            }

            # Track whether the most recent comment block carried a SAFETY-
            # marker. The block ends when a non-comment, non-blank line
            # appears (we treat that line as the protected statement).
            is_comment = ($0 ~ /^[[:space:]]*\/\//)
            is_blank   = ($0 ~ /^[[:space:]]*$/)
            if (is_comment) {
                if ($0 ~ /\/\/[[:space:]]*SAFETY-/) safety_active = 1
                next
            }

            same_line_safe = ($0 ~ /\/\/[[:space:]]*SAFETY-/)
            if (!same_line_safe && !safety_active &&
                ($0 ~ /\.unwrap\(\)/ || $0 ~ /\.expect\(/ || $0 ~ /panic!\(/)) {
                printf "%s:%d: %s\n", FILENAME, NR, $0
            }
            # The safety marker covers everything until the current
            # statement ends (line terminated by ;, {, or }). This lets a
            # single SAFETY- comment shield a multi-line expression chain.
            if (!is_blank && $0 ~ /[;{}][[:space:]]*$/) {
                safety_active = 0
            }
        }
    ' "$file")
done

if [[ $violations -eq 0 ]]; then
    echo "check_unwraps: no unannotated unwrap/expect/panic! in production code."
    exit 0
fi

echo "check_unwraps: found ${violations} unannotated unwrap/expect/panic! call(s):"
echo
echo "$report"
echo "Fix by replacing with proper error handling, or annotate with"
echo "  // SAFETY-UNWRAP: <why this can never fail>"
echo "on the line above (or trailing the same line)."
exit 1
