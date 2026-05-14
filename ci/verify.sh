#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p can-cli -p can-policy -p can-proxy -p can-sandbox -p can-net
./ci/check_ignored_tests.sh
./ci/check_unwraps.sh

# shellcheck for integration test scripts. Best-effort: skip locally if
# shellcheck isn't installed, but CI installs it explicitly.
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x -P "tests/integration" tests/integration/*.sh ci/*.sh
else
    echo "shellcheck not installed — skipping (install on CI)"
fi
