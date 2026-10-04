#!/usr/bin/env bash
# ============================================================================
# t_stream_seals.sh — every stream of a signed run ends with its seal
#                     (ADR-0016)
#
# Tests:
#   1. A signed run seals each stream that emitted events, the syscall
#      supervisor's included
#   2. Each stream has exactly one seal, and it is the stream's last event
#   3. With an exec allow-list, the supervisor reports each exec it decided
#      on as process_exec, allowed or blocked, before its seal
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "Stream seals"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; cleanup' EXIT

"$CAN" keygen "$WORK/seal.key" >/dev/null
EVENTS="$WORK/events.jsonl"

# A command that makes the supervisor decide something, so its stream is
# not empty: a child process, whose execve the supervisor sees.
run_can run --events-file "$EVENTS" --events-sign-key "$WORK/seal.key" --run-id r-seal \
    -- sh -c '/bin/true; echo ran'

REPORT=$(python3 - "$EVENTS" <<'PY'
import json, sys
streams = {}
for line in open(sys.argv[1], encoding="utf-8"):
    event = json.loads(line)
    streams.setdefault(event["stream"], []).append(event["event"])
for name in sorted(streams):
    events = streams[name]
    seals = events.count("stream_seal")
    last = "seal-last" if events[-1] == "stream_seal" else "unsealed"
    print(f"{name}:{seals}:{last}")
PY
)

begin_test "the run produced a supervisor stream"
assert_contains "$REPORT" "supervisor:"

begin_test "every stream ends with exactly one seal, the supervisor's included"
if echo "$REPORT" | grep -qv ':1:seal-last$'; then
    fail "streams without exactly one closing seal: $(echo "$REPORT" | grep -v ':1:seal-last$' | tr '\n' ' ')"
else
    pass
fi

SH_PATH=$(readlink -f "$(command -v sh)")
TRUE_PATH=$(readlink -f "$(command -v true)")
EXEC_RECIPE=$(tmpconfig <<TOML
[process]
exec = ["$SH_PATH", "$(command -v sh)", "$TRUE_PATH", "$(command -v true)"]
TOML
)
_TMPFILES+=("$EXEC_RECIPE")
EXEC_EVENTS="$WORK/exec.jsonl"

run_can run --recipe "$EXEC_RECIPE" --events-file "$EXEC_EVENTS" \
    --events-sign-key "$WORK/seal.key" --run-id r-exec \
    -- sh -c "$TRUE_PATH; /bin/ls >/dev/null 2>&1; echo ran"

SUPERVISED=$(python3 - "$EXEC_EVENTS" <<'PY'
import json, sys
events = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
supervisor = [e for e in events if e["stream"] == "supervisor"]
execs = [(e["data"]["path"].rsplit("/", 1)[-1], e["data"]["decision"]) for e in supervisor if e["event"] == "process_exec"]
print(" ".join(f"{name}:{decision}" for name, decision in execs))
print("sealed-last" if supervisor and supervisor[-1]["event"] == "stream_seal" else "unsealed")
PY
)

begin_test "the supervisor reports an exec it allowed"
assert_contains "$SUPERVISED" "true:allowed"

begin_test "the supervisor reports an exec it blocked"
assert_contains "$SUPERVISED" "ls:blocked"

begin_test "the supervisor's exec events come before its seal"
assert_contains "$SUPERVISED" "sealed-last"

summary
