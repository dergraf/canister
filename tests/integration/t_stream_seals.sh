#!/usr/bin/env bash
# ============================================================================
# t_stream_seals.sh — every stream of a signed run ends with its seal
#                     (ADR-0016)
#
# Tests:
#   1. A signed run seals each stream that emitted events, the syscall
#      supervisor's included
#   2. Each stream has exactly one seal, and it is the stream's last event
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

summary
