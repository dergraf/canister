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
    if bash "$test_file"; then
        (( PASSED++ )) || true
    else
        exit_code=$?
        if [[ $exit_code -eq 0 ]]; then
            (( SKIPPED++ )) || true
        else
            (( FAILED++ )) || true
            FAILURES+=("$(basename "$test_file")")
        fi
    fi
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
