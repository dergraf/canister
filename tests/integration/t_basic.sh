#!/usr/bin/env bash
# ============================================================================
# t_basic.sh — Basic sandbox execution
#
# Tests:
#   1. Simple echo command works
#   2. Exit code is propagated correctly (0, 1, 42)
#   3. Python script runs inside the sandbox
#   4. Nonexistent command fails with appropriate error
#   5. can check runs successfully
#   6. can recipe list shows default baseline info
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Basic sandbox execution"

# ---- Test 1: Simple echo ----
begin_test "echo command produces output"
run_can run -- echo "hello from the sandbox"
assert_eq "hello from the sandbox" "$RUN_STDOUT"

# ---- Test 2: Exit code 0 ----
begin_test "exit code 0 propagated"
run_can run -- true
assert_exit_code 0 "$RUN_EXIT"

# ---- Test 3: Exit code 1 ----
begin_test "exit code 1 propagated"
run_can run -- false
assert_exit_code 1 "$RUN_EXIT"

# ---- Test 4: Exit code 42 ----
begin_test "exit code 42 propagated"
run_can run -- sh -c "exit 42"
assert_exit_code 42 "$RUN_EXIT"

# ---- Test 5: Python script ----
if has_python3; then
    begin_test "python3 runs inside sandbox"
    run_can run -- python3 -c 'print("hello from the sandbox")'
    assert_contains "$RUN_STDOUT" "hello from the sandbox"
else
    begin_test "python3 runs inside sandbox"
    skip "python3 not available"
fi

# ---- Test 6: Nonexistent command ----
begin_test "nonexistent command fails"
run_can run -- /usr/bin/this_does_not_exist_canister_test
assert_neq 0 "$RUN_EXIT" "should fail for nonexistent command"

# ---- Test 7: can check ----
begin_test "can check succeeds"
run_can check
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "User namespaces"

# ---- Test 8: can recipe list ----
begin_test "can recipe list shows default baseline"
run_can recipe list
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "Discovered recipes"
assert_contains "$RUN_STDOUT" "Default baseline"
assert_contains "$RUN_STDOUT" "allowed"

summary
