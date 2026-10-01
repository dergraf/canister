#!/usr/bin/env bash
# ============================================================================
# t_tripwires.sh — Filesystem tripwires (ADR-0019)
#
# Tests:
#   1. Opening a decoy inside the sandbox is reported as fs_access, before run_end
#   2. A decoy holds nothing
#   3. A decoy aimed into the working directory is not placed, and the host
#      is untouched
#   4. A burst of accesses yields a bounded number of events
#   5. Without decoys, no fs_access event and no decoy directory
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Filesystem tripwires"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; cleanup' EXIT

# HOME is not mounted by the base recipe, so a decoy there is placed.
DECOY="${HOME}/.ssh/canister-tripwire-test"
cat > "${WORK}/recipe.toml" <<TOML
[filesystem]
decoy = ["${DECOY}", "${PWD}/.canister-decoy-in-cwd"]
TOML

begin_test "opening a decoy is reported as fs_access, before run_end"
run_can run --recipe "${WORK}/recipe.toml" --events-file "${WORK}/events.jsonl" \
    -- sh -c "cat '${DECOY}' && echo READ_OK:\$(wc -c < '${DECOY}')"
python3 - "${WORK}/events.jsonl" "${DECOY}" <<'PY' > "${WORK}/check.txt"
import json, sys
events = [json.loads(line) for line in open(sys.argv[1])]
names = [e["event"] for e in events]
hits = [e["data"] for e in events if e["event"] == "fs_access"]
ok = any(h["path"] == sys.argv[2] and h["operation"] == "open" and h["mechanism"] == "decoy"
         for h in hits)
last_access = max((i for i, n in enumerate(names) if n == "fs_access"), default=-1)
print("FS_ACCESS_OK" if ok else f"FS_ACCESS_MISSING {hits}")
print("BEFORE_RUN_END" if last_access < names.index("run_end") else "AFTER_RUN_END")
PY
assert_contains "$(cat "${WORK}/check.txt")" "FS_ACCESS_OK"
assert_contains "$(cat "${WORK}/check.txt")" "BEFORE_RUN_END"

begin_test "a decoy holds nothing"
assert_contains "$RUN_STDOUT" "READ_OK:0"

begin_test "a decoy aimed into the working directory is not placed"
if [[ -e "${PWD}/.canister-decoy-in-cwd" ]]; then
    fail "a decoy was created on the host"
    rm -f "${PWD}/.canister-decoy-in-cwd"
else
    pass
fi

begin_test "a burst of accesses yields a bounded number of events"
run_can run --recipe "${WORK}/recipe.toml" --events-file "${WORK}/burst.jsonl" \
    -- sh -c "for i in \$(seq 500); do cat '${DECOY}'; done"
BURST=$(python3 -c '
import json, sys
hits = [json.loads(l)["data"] for l in open(sys.argv[1]) if "\"fs_access\"" in l]
opens = [h for h in hits if h["operation"] == "open"]
print("BOUNDED" if 1 <= len(opens) <= 10 else f"UNBOUNDED {len(opens)}")
' "${WORK}/burst.jsonl")
assert_contains "$BURST" "BOUNDED"

begin_test "without decoys, no fs_access and no decoy directory"
count_decoy_dirs() { compgen -G "${TMPDIR:-/tmp}/can-decoys-*" | wc -l || true; }
before=$(count_decoy_dirs)
run_can run --events-file "${WORK}/plain.jsonl" -- /bin/true
after=$(count_decoy_dirs)
assert_not_contains "$(cat "${WORK}/plain.jsonl")" '"fs_access"'
if [[ "$before" == "$after" ]]; then pass; else fail "a decoy directory was left behind"; fi

summary
