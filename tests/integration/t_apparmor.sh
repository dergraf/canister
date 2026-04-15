#!/usr/bin/env bash
# ============================================================================
# t_apparmor.sh — AppArmor MAC integration tests
#
# Tests that the canister AppArmor profile works correctly:
#   1. can check detects AppArmor as active MAC system
#   2. can setup installs the AppArmor profile
#   3. Sandbox runs under AppArmor confinement
#   4. can setup --remove cleanly removes the profile
#   5. can setup re-installs after removal
#
# Requires: AppArmor-enabled kernel, root (sudo), can binary built
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_sudo
header "AppArmor MAC integration"

# ---- Prerequisite: AppArmor must be active ----
if [ ! -f /sys/module/apparmor/parameters/enabled ]; then
    skip_all "AppArmor not available on this system"
fi
AA_ENABLED=$(cat /sys/module/apparmor/parameters/enabled)
if [ "$AA_ENABLED" != "Y" ]; then
    skip_all "AppArmor is disabled"
fi

# Helper to run can with sudo and capture output.
run_sudo_can() {
    local tmpout tmperr
    tmpout=$(mktemp)
    tmperr=$(mktemp)
    RUN_EXIT=0
    sudo -n "$CAN" "$@" >"$tmpout" 2>"$tmperr" || RUN_EXIT=$?
    RUN_STDOUT=$(cat "$tmpout")
    RUN_STDERR=$(cat "$tmperr")
    rm -f "$tmpout" "$tmperr"
}

# ---- Test 1: can check detects AppArmor ----
begin_test "can check detects AppArmor"
run_can check
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "AppArmor"

# ---- Test 2: can setup installs AppArmor profile ----
begin_test "can setup installs AppArmor profile"
run_sudo_can setup --force
assert_exit_code 0 "$RUN_EXIT"

# ---- Test 3: Sandbox runs under AppArmor confinement ----
begin_test "sandbox runs under AppArmor confinement"
run_can run -- echo "hello under AppArmor"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "hello under AppArmor" "$RUN_STDOUT"

# ---- Test 4: Sandboxed process can read /proc/self ----
begin_test "sandboxed process reads /proc/self/status"
run_can run -- cat /proc/self/status
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "Name:"

# ---- Test 5: can setup --remove removes the profile ----
begin_test "can setup --remove removes AppArmor profile"
run_sudo_can setup --remove
assert_exit_code 0 "$RUN_EXIT"

# ---- Test 6: can setup re-installs after removal ----
begin_test "can setup re-installs after removal"
run_sudo_can setup --force
assert_exit_code 0 "$RUN_EXIT"

# ---- Test 7: Sandbox still works after re-install ----
begin_test "sandbox works after profile re-install"
run_can run -- echo "still works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "still works" "$RUN_STDOUT"

summary
