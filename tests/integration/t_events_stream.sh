#!/usr/bin/env bash
# ============================================================================
# t_events_stream.sh — structured event stream (ADR-0010, schema v1)
#
# Covers the CLI side of the contract:
#   * --events-file writes one JSON object per line, with a verifiable
#     hash chain and contiguous sequence numbers
#   * --run-id is stamped on every event
#   * --events-socket delivers the same lines to a listening consumer
#   * without an event flag, `can` emits no schema-v1 lines at all
#
# The proxy-stream side (egress_request, contract_violation, canary_fire)
# is covered by the Rust integration test
# crates/can-proxy/tests/events_stream.rs, which does not need pasta.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "Structured event stream (schema v1)"

CONFIG=$(tmpconfig <<'EOF'
[filesystem]
read = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/bin"]

[network]
egress = "none"

[process]
env_passthrough = ["PATH", "HOME", "LANG", "TERM"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

EVENTS_DIR=$(mktemp -d)
# lib.sh's cleanup only removes files; a directory needs its own trap,
# chained so the shared cleanup still runs.
trap 'rm -rf "$EVENTS_DIR"; cleanup' EXIT

# Shared checker: validates the envelope invariants of a JSONL stream and
# prints the event names it found, one per line.
CHECKER="${EVENTS_DIR}/check_events.py"
cat > "$CHECKER" <<'PYEOF'
import hashlib
import json
import sys

path, expected_run_id = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    lines = [line.rstrip("\n") for line in fh if line.strip()]

if not lines:
    print("FAIL no event lines")
    sys.exit(1)

MARKER = ',"chain_hash":"'
prev_by_stream = {}
seq_by_stream = {}
names = []

for line in lines:
    event = json.loads(line)

    if event["schema"] != 1:
        print(f"FAIL schema={event['schema']}")
        sys.exit(1)
    if event["run_id"] != expected_run_id:
        print(f"FAIL run_id={event['run_id']}")
        sys.exit(1)

    stream = event["stream"]

    # chain_hash covers the line with its own field removed.
    at = line.rfind(MARKER)
    body = line[:at] + "}"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    if digest != event["chain_hash"]:
        print(f"FAIL chain_hash mismatch on seq={event['seq']} stream={stream}")
        sys.exit(1)

    expected_prev = prev_by_stream.get(stream, "0" * 64)
    if event["prev_hash"] != expected_prev:
        print(f"FAIL prev_hash mismatch on seq={event['seq']} stream={stream}")
        sys.exit(1)
    prev_by_stream[stream] = event["chain_hash"]

    expected_seq = seq_by_stream.get(stream, 0)
    if event["seq"] != expected_seq:
        print(f"FAIL seq gap: got {event['seq']}, expected {expected_seq}")
        sys.exit(1)
    seq_by_stream[stream] = expected_seq + 1

    names.append(event["event"])

print("EVENTS_OK " + ",".join(names))
PYEOF

# ---------------------------------------------------------------------------
begin_test "--events-file records a verifiable run_start/process_exec/run_end chain"
EVENTS_FILE="${EVENTS_DIR}/run.jsonl"
run_can run --recipe "$CONFIG" \
    --events-file "$EVENTS_FILE" --run-id r-integration \
    -- /bin/echo hello

if [[ ! -s "$EVENTS_FILE" ]]; then
    fail "no events written to $EVENTS_FILE (stderr: $RUN_STDERR)"
else
    CHECK_OUT=$(python3 "$CHECKER" "$EVENTS_FILE" r-integration) || true
    case "$CHECK_OUT" in
        EVENTS_OK*run_start*policy_resolved*process_exec*run_end*) pass ;;
        *) fail "envelope check failed: $CHECK_OUT" ;;
    esac
fi

# ---------------------------------------------------------------------------
begin_test "run_end carries the workload's exit code"
EVENTS_FILE_EXIT="${EVENTS_DIR}/exit.jsonl"
run_can run --recipe "$CONFIG" \
    --events-file "$EVENTS_FILE_EXIT" --run-id r-exit \
    -- /bin/sh -c 'exit 3'

EXIT_CODE=$(python3 - "$EVENTS_FILE_EXIT" <<'PYEOF'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    event = json.loads(line)
    if event["event"] == "run_end":
        print(event["data"].get("exit_code", "missing"))
        break
else:
    print("no-run-end")
PYEOF
)
assert_eq "3" "$EXIT_CODE" "run_end exit_code"

# ---------------------------------------------------------------------------
begin_test "policy_resolved carries a hash that is stable across identical runs"
POLICY_A="${EVENTS_DIR}/policy_a.jsonl"
POLICY_B="${EVENTS_DIR}/policy_b.jsonl"
run_can run --recipe "$CONFIG" --events-file "$POLICY_A" --run-id r-policy-a -- /bin/echo one
run_can run --recipe "$CONFIG" --events-file "$POLICY_B" --run-id r-policy-b -- /bin/echo two

read_policy_hash() {
    python3 - "$1" <<'PYEOF'
import hashlib, json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    event = json.loads(line)
    if event["event"] != "policy_resolved":
        continue
    data = event["data"]
    # The hash must cover exactly the emitted policy document.
    canonical = json.dumps(data["policy"], sort_keys=True, separators=(",", ":"))
    recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    print(data["policy_sha256"] if recomputed == data["policy_sha256"] else "hash-mismatch")
    break
else:
    print("no-policy-event")
PYEOF
}

HASH_A=$(read_policy_hash "$POLICY_A")
HASH_B=$(read_policy_hash "$POLICY_B")
assert_eq "$HASH_A" "$HASH_B" "identical recipes produce the same policy hash"
case "$HASH_A" in
    hash-mismatch|no-policy-event) fail "policy_resolved check failed: $HASH_A" ;;
    *) pass ;;
esac

# ---------------------------------------------------------------------------
begin_test "a different policy produces a different hash"
CONFIG_B=$(tmpconfig <<'EOF'
[filesystem]
read = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/bin", "/etc"]

[network]
egress = "none"

[process]
env_passthrough = ["PATH", "HOME", "LANG", "TERM"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG_B")
POLICY_C="${EVENTS_DIR}/policy_c.jsonl"
run_can run --recipe "$CONFIG_B" --events-file "$POLICY_C" --run-id r-policy-c -- /bin/echo three
HASH_C=$(read_policy_hash "$POLICY_C")
assert_neq "$HASH_A" "$HASH_C" "a changed policy changes the hash"

# ---------------------------------------------------------------------------
begin_test "--events-socket delivers the same stream to a listening consumer"
SOCKET_PATH="${EVENTS_DIR}/events.sock"
SOCKET_OUT="${EVENTS_DIR}/socket.jsonl"

python3 - "$SOCKET_PATH" "$SOCKET_OUT" <<'PYEOF' &
import socket
import sys

path, out_path = sys.argv[1], sys.argv[2]
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
server.listen(8)
server.settimeout(60)

with open(out_path, "wb") as out:
    # One connection per emitting process; the CLI process is the one
    # that always connects.
    conn, _ = server.accept()
    with conn:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            out.write(chunk)
            out.flush()
PYEOF
LISTENER_PID=$!

# Wait for the socket to appear before starting can.
for _ in $(seq 1 50); do
    [[ -S "$SOCKET_PATH" ]] && break
    sleep 0.1
done

if [[ ! -S "$SOCKET_PATH" ]]; then
    kill "$LISTENER_PID" 2>/dev/null || true
    fail "listener never created $SOCKET_PATH"
else
    run_can run --recipe "$CONFIG" \
        --events-socket "$SOCKET_PATH" --run-id r-socket \
        -- /bin/echo socket

    wait "$LISTENER_PID" || true

    CHECK_OUT=$(python3 "$CHECKER" "$SOCKET_OUT" r-socket) || true
    case "$CHECK_OUT" in
        EVENTS_OK*run_start*run_end*) pass ;;
        *) fail "socket stream check failed: $CHECK_OUT" ;;
    esac
fi

# ---------------------------------------------------------------------------
begin_test "no event flags means no schema-v1 output (default behavior unchanged)"
run_can run --recipe "$CONFIG" -- /bin/echo quiet
assert_not_contains "$RUN_STDOUT" '"schema":1' "stdout must stay free of event lines"
assert_not_contains "$RUN_STDERR" '"schema":1' "stderr must stay free of event lines"

# ---------------------------------------------------------------------------
begin_test "--run-id without an event target is rejected"
run_can run --recipe "$CONFIG" --run-id r-orphan -- /bin/echo nope
assert_neq "0" "$RUN_EXIT" "can must fail"
assert_contains "$RUN_STDERR" "--run-id requires" "explains the missing flag"

summary
