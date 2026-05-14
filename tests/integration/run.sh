#!/usr/bin/env bash
# Integration test runner for canister.
# Runs all t_*.sh test files and reports a summary.
#
# Usage:
#   cargo build --workspace && ./tests/integration/run.sh
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PASSED=0
FAILED=0
SKIPPED=0
FAILURES=()

for test_file in "${TESTS_DIR}"/t_*.sh; do
    output_file=$(mktemp)
    set +e
    bash "$test_file" >"$output_file" 2>&1
    rc=$?
    set -e
    case "$rc" in
        0)
            (( PASSED++ )) || true
            ;;
        77)
            # Exit 77 = skip_all() from lib.sh (autoconf convention).
            (( SKIPPED++ )) || true
            ;;
        *)
            (( FAILED++ )) || true
            FAILURES+=("$(basename "$test_file") (exit $rc)")
            ;;
    esac
    cat "$output_file"
    rm -f "$output_file"
    echo ""
done

echo "============================================"
echo "Integration test summary"
echo "  Files: $((PASSED + FAILED + SKIPPED)) total"
echo "  Passed:  ${PASSED}"
echo "  Failed:  ${FAILED}"
echo "  Skipped: ${SKIPPED}"

if (( FAILED > 0 )); then
    echo ""
    echo "  Failed files:"
    for f in "${FAILURES[@]}"; do
        echo "    - $f"
    done
    echo "============================================"
    exit 1
fi
echo "============================================"
