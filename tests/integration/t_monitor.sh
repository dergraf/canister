#!/usr/bin/env bash
# ============================================================================
# t_monitor.sh — Monitor mode (observe without enforce)
#
# Tests:
#   1. Monitor mode runs successfully (exit 0 for a valid command)
#   2. Monitor mode emits MONITOR: log lines
#   3. Monitor mode shows policy summary
#   4. Monitor and strict are mutually exclusive
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Monitor mode"

CONFIG="${CONFIGS_DIR}/monitor.toml"

# ---- Test 1: Monitor mode runs ----
begin_test "monitor mode runs successfully"
run_can run --monitor --config "$CONFIG" -- echo "monitored"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "monitored" "$RUN_STDOUT"

# ---- Test 2: Monitor output in stderr ----
begin_test "monitor mode emits log output"
run_can run --monitor --config "$CONFIG" -- echo "test"
# Monitor mode should produce some log output (policy summary, etc.)
# The exact format depends on logging, but stderr should not be empty
assert_neq "" "$RUN_STDERR" "stderr should contain monitor output"

# ---- Test 3: Policy summary in output ----
begin_test "monitor mode shows policy info"
run_can run --monitor --config "$CONFIG" -- true
# Should mention monitor/observe in the stderr log
assert_contains "$RUN_STDERR" "monitor"

# ---- Test 4: Monitor + strict mutual exclusion ----
begin_test "monitor and strict are mutually exclusive"
run_can run --monitor --strict --config "$CONFIG" -- true
assert_neq 0 "$RUN_EXIT" "should reject --monitor --strict"

summary
