#!/usr/bin/env bash
# ============================================================================
# t_registry.sh — Recipe registry (can init / can update) tests
#
# Tests:
#   1. can init --help shows expected options
#   2. can update --help shows expected options
#   3. can init fails gracefully when repo is unreachable
#   4. can update fails gracefully when repo is unreachable
#   5. can init output mentions install directory
# ============================================================================

source "$(dirname "$0")/lib.sh"
header "Recipe registry (can init / can update)"

# ---- Test 1: can init --help ----
begin_test "can init --help shows expected options"
run_can init --help
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "--repo"
assert_contains "$RUN_STDOUT" "--branch"

# ---- Test 2: can update --help ----
begin_test "can update --help shows expected options"
run_can update --help
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "--repo"
assert_contains "$RUN_STDOUT" "--branch"

# ---- Test 3: can init fails gracefully for nonexistent repo ----
begin_test "can init fails gracefully for nonexistent repo"
INIT_DIR=$(mktemp -d)
_TMPFILES+=("$INIT_DIR")
# Use a repo that definitely doesn't exist.
XDG_CONFIG_HOME="$INIT_DIR" run_can init --repo "canister-sandbox/nonexistent-repo-xyz-999"
assert_neq 0 "$RUN_EXIT" "should fail for nonexistent repo"
# Should get a useful error message, not a crash.
assert_contains "$RUN_STDERR" "git clone failed"

# ---- Test 4: can update fails gracefully for nonexistent repo ----
begin_test "can update fails gracefully for nonexistent repo"
UPDATE_DIR=$(mktemp -d)
_TMPFILES+=("$UPDATE_DIR")
XDG_CONFIG_HOME="$UPDATE_DIR" run_can update --repo "canister-sandbox/nonexistent-repo-xyz-999"
assert_neq 0 "$RUN_EXIT" "should fail for nonexistent repo"
assert_contains "$RUN_STDERR" "git clone failed"

# ---- Test 5: Verify init output mentions install directory ----
begin_test "can init mentions install directory in output"
# Even though it will fail (repo doesn't exist), stdout should mention
# the install directory before the failure.
TEST_DIR=$(mktemp -d)
_TMPFILES+=("$TEST_DIR")
XDG_CONFIG_HOME="$TEST_DIR" run_can init --repo "canister-sandbox/nonexistent-repo-xyz-999"
# The first line of stdout should mention the install directory.
assert_contains "$RUN_STDOUT" "Installing recipes to:"
assert_contains "$RUN_STDOUT" "canister/recipes"

summary
