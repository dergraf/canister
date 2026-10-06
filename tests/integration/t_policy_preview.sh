#!/usr/bin/env bash
# ============================================================================
# t_policy_preview.sh — --print-policy previews what a run enforces (ADR-0033)
#
# Tests:
#   1. It prints the policy and the digest the run's policy_resolved event
#      carries, with every run-time input applied: a recipe, a canaries
#      file, a --port mapping and a canister.toml masked in the working
#      directory
#   2. It starts no sandbox
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "Policy preview"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; cleanup' EXIT
cd "$WORK" || exit 1
touch canister.toml

RECIPE=$(tmpconfig <<'TOML'
[network]
egress = "proxy"
undeclared_hosts = "sink"

[[host]]
domain = "api.example.com"
TOML
)
_TMPFILES+=("$RECIPE")
cat > canaries.json <<'JSON'
[{"value":"CNRY-PREVIEW-1","data_class":"ahv","allowed_hosts":["api.example.com"]}]
JSON

FLAGS=(--recipe "$RECIPE" --canaries-file canaries.json --port 8080:8080)

begin_test "it prints what the run's policy_resolved event carries"
run_can run "${FLAGS[@]}" --print-policy -- sh -c 'touch ran'
PREVIEW="$RUN_STDOUT"
run_can run "${FLAGS[@]}" --events-file events.jsonl -- true
SAME=$(python3 - "$PREVIEW" events.jsonl <<'PY'
import json, sys
preview = json.loads(sys.argv[1])
event = next(json.loads(l) for l in open(sys.argv[2]) if '"policy_resolved"' in l)["data"]
print(preview["policy_sha256"] == event["policy_sha256"] and preview["policy"] == event["policy"],
      "canister.toml" in json.dumps(preview["policy"]["filesystem"]["mask"]),
      "CNRY-PREVIEW-1" in json.dumps(preview["policy"]))
PY
)
assert_eq "True True True" "$SAME"

begin_test "it starts no sandbox"
assert_eq "0" "$RUN_EXIT"
if [ -e ran ]; then fail "the command ran"; else pass; fi

summary
