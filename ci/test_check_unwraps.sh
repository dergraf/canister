#!/usr/bin/env bash
# Self-test for ci/check_unwraps.sh. Builds a tiny synthetic workspace
# under a tmpdir, drops a copy of check_unwraps.sh in, and asserts that
# the script's exit code and output match what each fixture expects.
#
# Add a new case by writing a Rust fixture to fixtures/<name>/crates/X/src/lib.rs
# along with an `EXPECT_<name>` block at the bottom of this file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUARD="${SCRIPT_DIR}/check_unwraps.sh"

if [[ ! -x "$GUARD" ]]; then
    echo "fail: ${GUARD} not executable or missing" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Test harness
# ---------------------------------------------------------------------------

PASSED=0
FAILED=0
FAILURES=()

run_case() {
    local name="$1"
    local expected_exit="$2"
    local expected_pattern="$3"
    local fixture_content="$4"

    local tmp
    tmp=$(mktemp -d)
    mkdir -p "${tmp}/crates/fixture/src" "${tmp}/ci"
    printf '%s' "${fixture_content}" > "${tmp}/crates/fixture/src/lib.rs"
    cp "${GUARD}" "${tmp}/ci/check_unwraps.sh"

    local out exit_code=0
    out=$(cd "${tmp}" && bash ci/check_unwraps.sh 2>&1) || exit_code=$?

    local ok=1
    if [[ "${exit_code}" != "${expected_exit}" ]]; then
        ok=0
    fi
    if [[ -n "${expected_pattern}" && "${out}" != *"${expected_pattern}"* ]]; then
        ok=0
    fi

    if (( ok == 1 )); then
        echo "  PASS ${name}"
        PASSED=$(( PASSED + 1 ))
    else
        echo "  FAIL ${name}"
        echo "       expected exit=${expected_exit} pattern='${expected_pattern}'"
        echo "       got exit=${exit_code}, output:"
        printf '       | %s\n' "$(echo "${out}" | sed 's/^/  /')"
        FAILED=$(( FAILED + 1 ))
        FAILURES+=("${name}")
    fi

    rm -rf "${tmp}"
}

echo ">>> test_check_unwraps: self-test of the unwrap guard"

# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

# 1. Plain unannotated unwrap in production code → must fail.
run_case "bare unwrap fails the guard" 1 "found 1" "$(cat <<'EOF'
fn main() {
    let x: Result<i32, ()> = Ok(1);
    let y = x.unwrap();
    println!("{y}");
}
EOF
)"

# 2. Bare expect → must fail.
run_case "bare expect fails the guard" 1 "found 1" "$(cat <<'EOF'
fn main() {
    let x: Result<i32, ()> = Ok(1);
    let _ = x.expect("must succeed");
}
EOF
)"

# 3. panic! → must fail.
run_case "bare panic fails the guard" 1 "found 1" "$(cat <<'EOF'
fn explode() {
    panic!("nope");
}
EOF
)"

# 4. Trailing same-line SAFETY annotation accepts the call.
run_case "trailing SAFETY-UNWRAP accepted" 0 "no unannotated" "$(cat <<'EOF'
fn main() {
    let x: Result<i32, ()> = Ok(1);
    let y = x.unwrap(); // SAFETY-UNWRAP: constructed Ok just above
    println!("{y}");
}
EOF
)"

# 5. Multi-line preceding comment block carrying SAFETY accepts the call.
run_case "preceding multi-line SAFETY block accepted" 0 "no unannotated" "$(cat <<'EOF'
fn main() {
    let x: Result<i32, ()> = Ok(1);
    // SAFETY-UNWRAP: we just constructed an Ok above and never reassigned
    // x; this is a structural invariant the compiler can't see.
    let y = x.unwrap();
    println!("{y}");
}
EOF
)"

# 6. Multi-line statement chain protected by a single preceding SAFETY.
run_case "multi-line statement chain accepted" 0 "no unannotated" "$(cat <<'EOF'
fn main() {
    let v = vec![Ok::<_, ()>(1), Ok(2)];
    // SAFETY-UNWRAP: vec is non-empty by construction
    let first = v
        .into_iter()
        .next()
        .unwrap()
        .unwrap();
    println!("{first}");
}
EOF
)"

# 7. Unwrap inside #[cfg(test)] mod tests is silently allowed.
run_case "unwrap inside #[cfg(test)] module accepted" 0 "no unannotated" "$(cat <<'EOF'
fn produce() -> Result<i32, ()> { Ok(1) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t() {
        let v = produce().unwrap();
        assert_eq!(v, 1);
    }
}
EOF
)"

# 8. After a #[cfg(test)] module closes, production unwraps are flagged again.
run_case "unwrap after #[cfg(test)] module flagged" 1 "found 1" "$(cat <<'EOF'
#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        let x: Result<i32, ()> = Ok(1);
        let _ = x.unwrap();
    }
}

fn after_tests() {
    let x: Result<i32, ()> = Ok(2);
    let _ = x.unwrap();
}
EOF
)"

# 9. Stale SAFETY from a previous statement does NOT bleed through.
run_case "SAFETY scope ends at statement terminator" 1 "found 1" "$(cat <<'EOF'
fn main() {
    let a: Result<i32, ()> = Ok(1);
    // SAFETY-UNWRAP: a is Ok by construction
    let _ = a.unwrap();
    let b: Result<i32, ()> = Ok(2);
    let _ = b.unwrap();  // <-- this one is unprotected
}
EOF
)"

# 10. Multiple unannotated calls in one file are all reported.
run_case "multiple violations all reported" 1 "found 3" "$(cat <<'EOF'
fn main() {
    let a: Result<i32, ()> = Ok(1);
    let _ = a.unwrap();
    let b: Result<i32, ()> = Ok(2);
    let _ = b.expect("x");
    panic!("explode");
}
EOF
)"

# 11. Empty crate (no production .rs files) → zero violations, exit 0.
run_case "empty crate passes" 0 "no unannotated" "// nothing here"

# 12. nested mod tests with deeper braces still tracked correctly.
run_case "nested braces inside test mod still ignored" 0 "no unannotated" "$(cat <<'EOF'
#[cfg(test)]
mod tests {
    fn helper() -> Result<i32, ()> { Ok(1) }
    fn run() {
        if let Ok(v) = helper() {
            // unwrap inside a deeper block, still under tests
            assert_eq!(v, helper().unwrap());
        }
    }
}
EOF
)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

TOTAL=$(( PASSED + FAILED ))
echo
echo "  Results: ${PASSED} passed, ${FAILED} failed (${TOTAL} total)"

if (( FAILED > 0 )); then
    echo
    echo "  Failed cases:"
    for f in "${FAILURES[@]}"; do
        echo "    - $f"
    done
    exit 1
fi
exit 0
