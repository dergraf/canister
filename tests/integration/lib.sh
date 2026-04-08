#!/usr/bin/env bash
# ============================================================================
# Canister Integration Test Library
#
# Shared helpers for all t_*.sh test scripts. Source this file at the top
# of every test:
#
#   source "$(dirname "$0")/lib.sh"
#
# Provides:
#   - Capability detection (skip tests that need unavailable features)
#   - Assertion functions (assert_eq, assert_contains, assert_exit_code, ...)
#   - Test lifecycle (begin_test, pass, fail, skip, summary)
#   - Colored output (auto-detected)
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# Root of the canister project (two levels up from tests/integration/)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Binary location — prefer release build, fall back to debug
if [[ -x "${REPO_ROOT}/target/release/can" ]]; then
    CAN="${REPO_ROOT}/target/release/can"
elif [[ -x "${REPO_ROOT}/target/debug/can" ]]; then
    CAN="${REPO_ROOT}/target/debug/can"
else
    echo "ERROR: 'can' binary not found. Run 'cargo build' first." >&2
    exit 1
fi

CONFIGS_DIR="$(dirname "${BASH_SOURCE[0]}")/configs"

# ---------------------------------------------------------------------------
# Colors (disabled if not a terminal or NO_COLOR is set)
# ---------------------------------------------------------------------------

if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' BLUE='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

_TESTS_PASSED=0
_TESTS_FAILED=0
_TESTS_SKIPPED=0
_CURRENT_TEST=""

# ---------------------------------------------------------------------------
# Capability Detection
#
# These mirror what `can check` detects. Tests can call require_* at the top
# to skip gracefully when the feature is unavailable.
# ---------------------------------------------------------------------------

has_user_namespaces() {
    [[ -f /proc/sys/kernel/unprivileged_userns_clone ]] &&
        [[ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" == "1" ]] && return 0
    # If the sysctl doesn't exist, user namespaces are likely available
    # (most modern kernels). Try a quick unshare to be sure.
    unshare --user true 2>/dev/null
}

has_slirp4netns() {
    command -v slirp4netns &>/dev/null
}

has_cgroups_v2() {
    [[ -f /sys/fs/cgroup/cgroup.controllers ]]
}

has_python3() {
    command -v python3 &>/dev/null
}

require_user_namespaces() {
    if ! has_user_namespaces; then
        skip_all "user namespaces not available"
    fi
}

require_slirp4netns() {
    if ! has_slirp4netns; then
        skip_all "slirp4netns not installed"
    fi
}

require_cgroups_v2() {
    if ! has_cgroups_v2; then
        skip_all "cgroups v2 not available"
    fi
}

require_python3() {
    if ! has_python3; then
        skip_all "python3 not installed"
    fi
}

# Skip the entire test file with a reason.
skip_all() {
    local reason="$1"
    echo -e "${YELLOW}SKIP${RESET} $(basename "$0"): ${reason}"
    exit 0
}

# ---------------------------------------------------------------------------
# Test Lifecycle
# ---------------------------------------------------------------------------

# Start a named test case.
begin_test() {
    _CURRENT_TEST="$1"
}

# Mark the current test as passed.
pass() {
    (( _TESTS_PASSED++ )) || true
    echo -e "  ${GREEN}PASS${RESET} ${_CURRENT_TEST}"
}

# Mark the current test as failed with a message and continue.
fail() {
    local msg="${1:-}"
    (( _TESTS_FAILED++ )) || true
    echo -e "  ${RED}FAIL${RESET} ${_CURRENT_TEST}"
    if [[ -n "$msg" ]]; then
        echo -e "       ${msg}"
    fi
}

# Skip a single test case.
skip() {
    local reason="${1:-}"
    (( _TESTS_SKIPPED++ )) || true
    echo -e "  ${YELLOW}SKIP${RESET} ${_CURRENT_TEST}: ${reason}"
}

# Print the file-level header.
header() {
    echo -e "${BOLD}${BLUE}>>> $(basename "$0")${RESET}: $1"
}

# Print summary and exit with appropriate code.
# Call this at the end of every test file.
summary() {
    echo ""
    local total=$(( _TESTS_PASSED + _TESTS_FAILED + _TESTS_SKIPPED ))
    echo -e "  ${BOLD}Results:${RESET} ${GREEN}${_TESTS_PASSED} passed${RESET}, ${RED}${_TESTS_FAILED} failed${RESET}, ${YELLOW}${_TESTS_SKIPPED} skipped${RESET} (${total} total)"

    if (( _TESTS_FAILED > 0 )); then
        exit 1
    fi
    exit 0
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

# assert_eq <expected> <actual> [message]
assert_eq() {
    local expected="$1" actual="$2" msg="${3:-}"
    if [[ "$expected" == "$actual" ]]; then
        pass
    else
        fail "expected: '${expected}', got: '${actual}'${msg:+ ($msg)}"
    fi
}

# assert_neq <not_expected> <actual> [message]
assert_neq() {
    local not_expected="$1" actual="$2" msg="${3:-}"
    if [[ "$not_expected" != "$actual" ]]; then
        pass
    else
        fail "expected not '${not_expected}', but got it${msg:+ ($msg)}"
    fi
}

# assert_contains <haystack> <needle> [message]
assert_contains() {
    local haystack="$1" needle="$2" msg="${3:-}"
    if [[ "$haystack" == *"$needle"* ]]; then
        pass
    else
        fail "output does not contain '${needle}'${msg:+ ($msg)}"
    fi
}

# assert_not_contains <haystack> <needle> [message]
assert_not_contains() {
    local haystack="$1" needle="$2" msg="${3:-}"
    if [[ "$haystack" != *"$needle"* ]]; then
        pass
    else
        fail "output unexpectedly contains '${needle}'${msg:+ ($msg)}"
    fi
}

# assert_exit_code <expected_code> <actual_code> [message]
assert_exit_code() {
    local expected="$1" actual="$2" msg="${3:-}"
    if [[ "$expected" == "$actual" ]]; then
        pass
    else
        fail "expected exit code ${expected}, got ${actual}${msg:+ ($msg)}"
    fi
}

# assert_file_exists <path> [message]
assert_file_exists() {
    local path="$1" msg="${2:-}"
    if [[ -e "$path" ]]; then
        pass
    else
        fail "file does not exist: ${path}${msg:+ ($msg)}"
    fi
}

# assert_match <string> <regex> [message]
assert_match() {
    local string="$1" regex="$2" msg="${3:-}"
    if [[ "$string" =~ $regex ]]; then
        pass
    else
        fail "output does not match regex '${regex}'${msg:+ ($msg)}"
    fi
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Run a command, capture stdout+stderr and exit code.
# Usage: run_can [args...]
# Sets: RUN_STDOUT, RUN_STDERR, RUN_EXIT
run_can() {
    local tmpout tmperr
    tmpout=$(mktemp)
    tmperr=$(mktemp)
    RUN_EXIT=0
    "$CAN" "$@" >"$tmpout" 2>"$tmperr" || RUN_EXIT=$?
    RUN_STDOUT=$(cat "$tmpout")
    RUN_STDERR=$(cat "$tmperr")
    rm -f "$tmpout" "$tmperr"
}

# Create a temporary TOML config and return its path.
# Usage: tmpconfig <<'EOF'
#   [filesystem]
#   ...
# EOF
tmpconfig() {
    local tmp
    tmp=$(mktemp --suffix=.toml)
    cat > "$tmp"
    echo "$tmp"
}

# Cleanup temp files on exit.
_TMPFILES=()
cleanup() {
    for f in "${_TMPFILES[@]}"; do
        rm -f "$f" 2>/dev/null || true
    done
}
trap cleanup EXIT
