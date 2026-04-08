#!/usr/bin/env bash
# ============================================================================
# t_seccomp.sh — Seccomp BPF syscall filtering
#
# Tests:
#   1. mount() is denied (all profiles block it)
#   2. reboot() is denied (all profiles block it)
#   3. unshare() is denied (namespace escape blocked)
#   4. Allow-list mode works (python profile)
#   5. Deny-list mode works (python profile, legacy)
#   6. Strict mode kills process on denied syscall
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "Seccomp BPF syscall filtering"

AL_CONFIG="${CONFIGS_DIR}/seccomp_allowlist.toml"
DL_CONFIG="${CONFIGS_DIR}/seccomp_denylist.toml"
STRICT_CONFIG="${CONFIGS_DIR}/strict.toml"

# Inline python scripts for syscall tests — these use ctypes to invoke
# raw syscalls, which is the only reliable way to test seccomp filtering.

TRY_MOUNT='
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
ret = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
errno = ctypes.get_errno()
if ret == -1:
    print(f"OK: mount() denied (errno={errno})")
    sys.exit(0)
else:
    print("FAIL: mount() succeeded")
    sys.exit(1)
'

TRY_REBOOT='
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
RB_DISABLE_CAD = 0
ret = libc.reboot(RB_DISABLE_CAD)
errno = ctypes.get_errno()
if ret == -1:
    print(f"OK: reboot() denied (errno={errno})")
    sys.exit(0)
else:
    print("FAIL: reboot() succeeded")
    sys.exit(1)
'

TRY_UNSHARE='
import ctypes, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
CLONE_NEWUSER = 0x10000000
ret = libc.unshare(CLONE_NEWUSER)
errno = ctypes.get_errno()
if ret == -1:
    print(f"OK: unshare() denied (errno={errno})")
    sys.exit(0)
else:
    print("FAIL: unshare() succeeded — namespace escape possible!")
    sys.exit(1)
'

# ---- Test 1: mount() denied in allow-list mode ----
begin_test "mount() denied (allow-list mode)"
run_can run --config "$AL_CONFIG" -- python3 -c "$TRY_MOUNT"
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "OK: mount()"

# ---- Test 2: reboot() denied in allow-list mode ----
begin_test "reboot() denied (allow-list mode)"
run_can run --config "$AL_CONFIG" -- python3 -c "$TRY_REBOOT"
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "OK: reboot() denied"

# ---- Test 3: unshare() denied ----
begin_test "unshare() denied (namespace escape blocked)"
run_can run --config "$AL_CONFIG" -- python3 -c "$TRY_UNSHARE"
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "OK: unshare() denied"

# ---- Test 4: mount() denied in deny-list mode ----
begin_test "mount() denied (deny-list mode)"
run_can run --config "$DL_CONFIG" -- python3 -c "$TRY_MOUNT"
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "OK: mount()"

# ---- Test 5: reboot() denied in deny-list mode ----
begin_test "reboot() denied (deny-list mode)"
run_can run --config "$DL_CONFIG" -- python3 -c "$TRY_REBOOT"
assert_exit_code 0 "$RUN_EXIT"
assert_contains "$RUN_STDOUT" "OK: reboot() denied"

# ---- Test 6: Strict mode kills on denied syscall ----
begin_test "strict mode kills process on denied syscall"
run_can run --config "$STRICT_CONFIG" -- python3 -c "$TRY_MOUNT"
# In strict mode, the process should be killed (SIGSYS = signal 31, exit 159)
# rather than getting EPERM. The process won't print "OK" because it's dead.
assert_neq 0 "$RUN_EXIT" "process should be killed"
# The exit code for SIGSYS kill is 128+31=159 on most systems
# But the sandbox may report it differently. Key thing: it didn't exit 0.

# Verify the process did NOT get to print the "OK" line (it was killed before)
assert_not_contains "$RUN_STDOUT" "OK: mount()" "process should be killed before printing"

summary
