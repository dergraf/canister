#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p can-cli -p can-policy -p can-proxy -p can-sandbox -p can-net
./ci/check_ignored_tests.sh
./ci/check_unwraps.sh
./ci/test_check_unwraps.sh

# Run shell-script linter on integration tests. Best-effort: skip locally
# when not installed; CI installs it explicitly.
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -S error -x -P "tests/integration" tests/integration/*.sh ci/*.sh
else
    echo "(shellcheck unavailable, skipping; CI installs it explicitly)"
fi
