#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

matches=$(rg -n "ignore\s*=\s*\"" "$ROOT_DIR/crates" --glob "**/*.rs" || true)

if [[ -z "$matches" ]]; then
  echo "No ignored tests found."
  exit 0
fi

echo "Ignored tests found:"
echo "$matches"

if echo "$matches" | rg -v "owner=.*expiry=" | rg -v "disabled unless" >/dev/null; then
  echo "ERROR: ignored tests must include owner and expiry in the reason string."
  exit 1
fi

echo "Ignored tests metadata check passed."
