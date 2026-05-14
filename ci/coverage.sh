#!/usr/bin/env bash
# Local coverage runner. Mirrors what the CI `coverage` job does so
# contributors can reproduce + investigate failures without pushing.
#
# Usage:
#   ./ci/coverage.sh              # run + print summary
#   ./ci/coverage.sh --html       # additionally open an HTML report
#   ./ci/coverage.sh --lcov out   # write lcov.info to <out>
#
# Requires `cargo-llvm-cov` (auto-install if missing) and rustup
# components `llvm-tools-preview` for the host toolchain.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# Line-coverage floor enforced in CI. Currently set to the cargo-only
# baseline (the CI job runs cargo tests, not the bash integration suite
# under instrumentation). Combined coverage (unit + integration) is ~58%;
# the gap reflects the supervisor / namespace orchestration code that
# only runs in spawned children. Ratchet upward as new tests land —
# never down without explicit discussion. See `docs/coverage.md` (TODO)
# for the path to 90%.
THRESHOLD="${COVERAGE_THRESHOLD:-45}"

HTML=0
LCOV_OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --html) HTML=1; shift ;;
        --lcov) LCOV_OUT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "Installing cargo-llvm-cov (one-time, ~30s)..."
    cargo install --quiet cargo-llvm-cov --locked
fi

rustup component add llvm-tools-preview --quiet >/dev/null 2>&1 || true

# Exclude crates that generate docs / are essentially scaffolding so the
# coverage number reflects the runtime behaviour. `can-docgen` runs
# `can --help` and stringly templates markdown — not useful to gate on.
COVERAGE_ARGS=(
    --workspace
    --exclude can-docgen
    --ignore-filename-regex 'tests/.*'
)

echo "==> Running tests with coverage instrumentation"
cargo llvm-cov clean --workspace >/dev/null
cargo llvm-cov "${COVERAGE_ARGS[@]}" --summary-only \
    --fail-under-lines "$THRESHOLD"

if [[ -n "$LCOV_OUT" ]]; then
    echo "==> Writing lcov.info to $LCOV_OUT"
    cargo llvm-cov report "${COVERAGE_ARGS[@]}" --lcov --output-path "$LCOV_OUT"
fi

if [[ "$HTML" == 1 ]]; then
    echo "==> Generating HTML report"
    cargo llvm-cov report "${COVERAGE_ARGS[@]}" --html --open
fi
