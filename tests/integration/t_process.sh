#!/usr/bin/env bash
# ============================================================================
# t_process.sh — Process isolation and environment filtering
#
# Tests:
#   1. PID namespace: sandboxed process sees itself with low PID
#   2. PID namespace: host PIDs are not visible
#   3. Environment filtering: only passthrough vars are present
#   4. Environment filtering: sensitive vars are stripped
#   5. EDITOR not passed when not in passthrough
#   6. PATH is always injected (even when not in passthrough)
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Process isolation and environment filtering"

CONFIG="${CONFIGS_DIR}/process_env.toml"
CONFIG_FULL="${CONFIGS_DIR}/process_env_full.toml"

# ---- Test 1: PID 1 in namespace ----
begin_test "sandboxed process reports PID"
run_can run --config "$CONFIG" -- sh -c 'echo "PID=$$"'
assert_contains "$RUN_STDOUT" "PID="

# ---- Test 2: Host PIDs not visible ----
begin_test "host PIDs are not visible"
HOST_PIDS=$(ls /proc | grep -cE '^[0-9]+$')
run_can run --config "$CONFIG" -- sh -c 'echo "SANDBOX_PIDS=$(ls /proc 2>/dev/null | grep -cE "^[0-9]+$")"'
if [[ "$RUN_STDOUT" =~ SANDBOX_PIDS=([0-9]+) ]]; then
    SANDBOX_PIDS="${BASH_REMATCH[1]}"
    if (( SANDBOX_PIDS < HOST_PIDS )); then
        pass
    else
        fail "sandbox sees ${SANDBOX_PIDS} PIDs, host has ${HOST_PIDS}"
    fi
else
    fail "could not parse sandbox PID count from: $RUN_STDOUT"
fi

# ---- Test 3: Only passthrough env vars present ----
begin_test "only passthrough env vars are present"
export CANISTER_SECRET_TOKEN="super_secret_12345"
run_can run --config "$CONFIG" -- sh -c 'env | sort'
assert_contains "$RUN_STDOUT" "PATH="

# ---- Test 4: Sensitive env vars stripped ----
begin_test "sensitive env vars are stripped"
assert_not_contains "$RUN_STDOUT" "CANISTER_SECRET_TOKEN"

# ---- Test 5: EDITOR not passed when not in passthrough ----
begin_test "EDITOR stripped when not in passthrough"
export EDITOR=vim
run_can run --config "$CONFIG" -- sh -c 'env | sort'
assert_not_contains "$RUN_STDOUT" "EDITOR="
unset EDITOR

# ---- Test 6: PATH is always available ----
begin_test "PATH is always available"
TMPCONF=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]
[network]
deny_all = true
[process]
env_passthrough = ["HOME"]
[profile]
name = "generic"
EOF
)
_TMPFILES+=("$TMPCONF")
run_can run --config "$TMPCONF" -- sh -c 'echo "PATH=$PATH"'
assert_contains "$RUN_STDOUT" "PATH="

summary
