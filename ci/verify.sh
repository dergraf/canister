#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p can-proxy -p can-sandbox -p can-net
./ci/check_ignored_tests.sh
