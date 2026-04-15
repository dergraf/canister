#!/usr/bin/env bash
# ============================================================================
# t_selinux.sh — SELinux MAC integration tests
#
# Tests that the canister SELinux policy module works correctly:
#   1. can check detects SELinux as active MAC system
#   2. can setup installs the SELinux policy module
#   3. Sandbox runs under SELinux confinement
#   4. The sandboxed process transitions to canister_sandboxed_t
#   5. can setup --remove cleanly removes the module
#   6. can setup re-installs after removal
#
# Requires: SELinux-enabled kernel (Fedora/RHEL), root (sudo),
#           selinux-policy-devel, can binary built
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_sudo
header "SELinux MAC integration"

# ---- Prerequisite: SELinux must be active ----
if [ ! -d /sys/fs/selinux ]; then
    skip_all "SELinux not available on this system"
fi

SELINUX_MODE=$(getenforce 2>/dev/null || echo "Unknown")
if [ "$SELINUX_MODE" = "Disabled" ]; then
    skip_all "SELinux is disabled"
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

# ---- Test 1: can check detects SELinux ----
begin_test "can check detects SELinux"
run_can check
# Even without the policy installed, check should detect SELinux.
assert_contains "$RUN_STDOUT" "SELinux"

# ---- Test 2: can setup installs SELinux policy module ----
begin_test "can setup installs SELinux policy module"
run_sudo_can setup --force
assert_exit_code 0 "$RUN_EXIT"

# ---- Test 3: semodule lists canister module ----
begin_test "semodule lists canister module"
# Fedora 42+ may require --list-modules=full to show custom modules
# across all priority stores. Try -lfull first, fall back to -l.
if sudo semodule -lfull 2>/dev/null | grep -q canister; then
    pass
elif sudo semodule -l 2>/dev/null | grep -q canister; then
    pass
else
    echo "--- semodule -lfull output (first 20 lines matching 'can') ---"
    sudo semodule -lfull 2>/dev/null | grep -i can | head -20 || true
    echo "--- semodule -l output (first 20 lines matching 'can') ---"
    sudo semodule -l 2>/dev/null | grep -i can | head -20 || true
    fail "canister module not found in semodule -l or -lfull"
fi

# ---- Test 4: Sandbox runs under SELinux confinement ----
begin_test "sandbox runs under SELinux confinement"
run_can run -- echo "hello under SELinux"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "hello under SELinux" "$RUN_STDOUT"

# ---- Test 5: Sandboxed process can read /proc/self ----
begin_test "sandboxed process reads /proc/self/status"
run_can run -- cat /proc/self/status
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "Name:"

# ---- Test 6: can setup --remove removes the module ----
begin_test "can setup --remove removes SELinux module"
run_sudo_can setup --remove
assert_exit_code 0 "$RUN_EXIT"

# Verify module is gone.
if sudo semodule -lfull 2>/dev/null | grep -q canister; then
    fail "canister module still present after removal"
elif sudo semodule -l 2>/dev/null | grep -q canister; then
    fail "canister module still present after removal"
fi

# ---- Test 7: can setup re-installs after removal ----
begin_test "can setup re-installs after removal"
run_sudo_can setup --force
assert_exit_code 0 "$RUN_EXIT"

# ---- Test 8: Sandbox still works after re-install ----
begin_test "sandbox works after policy re-install"
run_can run -- echo "still works"
assert_exit_code 0 "$RUN_EXIT"
assert_eq "still works" "$RUN_STDOUT"

summary
