#!/usr/bin/env bash
# ============================================================================
# t_lock.sh — canister.lock and recipe sources (ADR-0026)
#
# Tests:
#   1. `can lock` writes canister.lock for a project's sources and recipes
#   2. A recipe the lock pins keeps its credential scope under `can up`
#   3. Without the lock, the same recipe's scope is dropped
#   4. A recipe changed since it was locked stops `can up`
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "Lockfile and recipe sources"

PROJECT=$(mktemp -d)
trap 'rm -rf "$PROJECT"; cleanup' EXIT
mkdir -p "$PROJECT/recipes"
cd "$PROJECT" || exit 1

cat > recipes/internal.toml <<'TOML'
[[host]]
domain = "internal.example"
allow_credentials = ["internal_token"]
TOML

cat > canister.toml <<'TOML'
[sources]
team = { path = "recipes" }

[sandbox.ci]
recipes = ["team/internal"]
command = "true"
TOML

scope() {
    python3 - "$1" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    event = json.loads(line)
    if event["event"] == "policy_resolved":
        hosts = event["data"]["policy"].get("host", [])
        found = [h.get("allow_credentials", []) for h in hosts if h.get("domain") == "internal.example"]
        print(",".join(found[0]) if found else "no-host")
PY
}

begin_test "can lock writes canister.lock"
run_can lock
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$(cat canister.lock 2>/dev/null)" '"team/internal" = "'

begin_test "a recipe the lock pins keeps its credential scope"
run_can up --events-file "$PROJECT/pinned.jsonl"
assert_eq "internal_token" "$(scope "$PROJECT/pinned.jsonl")"

begin_test "without the lock, the same recipe's scope is dropped"
mv canister.lock canister.lock.off
run_can up --events-file "$PROJECT/unpinned.jsonl"
assert_eq "" "$(scope "$PROJECT/unpinned.jsonl")"
mv canister.lock.off canister.lock

begin_test "a recipe changed since it was locked stops can up"
echo '# edited' >> recipes/internal.toml
run_can up
assert_neq 0 "$RUN_EXIT" "exit code"
assert_contains "$RUN_STDERR" "changed since it was locked"

summary
