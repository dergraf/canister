#!/usr/bin/env bash
# ============================================================================
# t_filesystem.sh — Filesystem isolation
#
# Tests:
#   1. Essential paths (/bin, /usr, /proc, /dev) exist inside the sandbox
#   2. /tmp is writable
#   3. Denied paths (/etc/shadow) are not visible
#   4. Host home directory is not visible (not in allow list)
#   5. Writes are ephemeral (not visible after exit)
#   6. Python cannot read /etc/shadow
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Filesystem isolation"

CONFIG="${CONFIGS_DIR}/filesystem_deny.toml"

# ---- Test 1: Essential paths exist ----
begin_test "essential paths exist (/bin, /usr, /proc, /dev)"
run_can run --config "$CONFIG" -- sh -c '
    for path in /bin /usr /proc /dev /tmp /etc/shadow /root /home; do
        if [ -e "$path" ]; then
            echo "EXISTS:$path"
        else
            echo "MISSING:$path"
        fi
    done
    if echo "canister_test" > /tmp/.canister_fs_test 2>/dev/null; then
        echo "TMP_WRITABLE=yes"
        rm -f /tmp/.canister_fs_test
    else
        echo "TMP_WRITABLE=no"
    fi
'
assert_contains "$RUN_STDOUT" "EXISTS:/bin"
assert_contains "$RUN_STDOUT" "EXISTS:/usr"
assert_contains "$RUN_STDOUT" "EXISTS:/proc"
assert_contains "$RUN_STDOUT" "EXISTS:/dev"

# ---- Test 2: /tmp is writable ----
begin_test "/tmp is writable"
assert_contains "$RUN_STDOUT" "TMP_WRITABLE=yes"

# ---- Test 3: /etc/shadow denied ----
begin_test "/etc/shadow is not visible"
assert_contains "$RUN_STDOUT" "MISSING:/etc/shadow"

# ---- Test 4: /root denied ----
begin_test "/root is not visible"
assert_contains "$RUN_STDOUT" "MISSING:/root"

# ---- Test 5: Writes are ephemeral ----
begin_test "writes to /tmp are ephemeral"
MARKER="/tmp/.canister_ephemeral_test_$$"
run_can run --config "$CONFIG" -- sh -c "echo test > ${MARKER}"
if [[ -e "$MARKER" ]]; then
    fail "marker file leaked to host filesystem"
else
    pass
fi

# ---- Test 6: Python script can't read /etc/shadow ----
if has_python3; then
    begin_test "python3 cannot read /etc/shadow"
    run_can run --config "$CONFIG" -- python3 -c '
import sys
try:
    with open("/etc/shadow") as f:
        print(f"FAIL: read /etc/shadow: {f.readline()[:20]}...")
        sys.exit(1)
except (PermissionError, FileNotFoundError) as e:
    print(f"OK: /etc/shadow blocked: {e}")
    sys.exit(0)
'
    assert_contains "$RUN_STDOUT" "OK: /etc/shadow blocked"
else
    begin_test "python3 cannot read /etc/shadow"
    skip "python3 not available"
fi

summary
