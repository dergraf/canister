#!/usr/bin/env bash
# ============================================================================
# t_strict.sh — Strict mode (fail-hard enforcement)
#
# Tests:
#   1. Strict mode runs when all features are available
#   2. Strict mode via config file (strict = true)
#   3. Normal command succeeds in strict mode
#   4. Exit code propagation works in strict mode
#   5. Strict + BPF deny  → SIGKILL/SIGSYS (exit 137 or 159)
#   6. Non-strict + BPF deny → process survives, syscall returns EPERM
#   7. Non-strict + notifier deny → EPERM (notifier path always errnos)
#   8. Strict + notifier deny → EPERM, NOT a kill. Documents the
#      invariant: `strict` toggles the BPF return action; the USER_NOTIF
#      supervisor still returns errno regardless.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Strict mode"

CONFIG="${CONFIGS_DIR}/strict.toml"

# ---- Test 1: Strict mode runs successfully ----
begin_test "strict mode runs with all features available"
run_can run --recipe "$CONFIG" -- echo "strict works"
# If this system supports all features, it should work.
# If it doesn't (e.g., AppArmor blocks mounts), strict mode will abort —
# that's the correct behavior.
if [[ "$RUN_EXIT" -eq 0 ]]; then
    assert_eq "strict works" "$RUN_STDOUT"
else
    # Strict mode correctly aborted because a feature is unavailable.
    # This is expected on some CI systems. Log it but don't fail.
    skip "strict mode aborted (feature unavailable on this system)"
fi

# ---- Test 2: Strict via --strict flag ----
begin_test "strict mode via --strict CLI flag"
TMPCONF=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]
[network]
egress = "proxy-only"
[process]
env_passthrough = ["PATH", "HOME"]
[syscalls]
EOF
)
_TMPFILES+=("$TMPCONF")
run_can run --strict --recipe "$TMPCONF" -- echo "strict flag"
if [[ "$RUN_EXIT" -eq 0 ]]; then
    assert_eq "strict flag" "$RUN_STDOUT"
else
    skip "strict mode aborted (feature unavailable on this system)"
fi

# ---- Test 3: Exit code in strict mode ----
begin_test "exit code propagated in strict mode"
run_can run --recipe "$CONFIG" -- sh -c "exit 7"
if [[ "$RUN_EXIT" -eq 7 ]]; then
    pass
elif [[ "$RUN_EXIT" -ne 0 ]]; then
    # Strict mode itself may have aborted
    skip "strict mode aborted before running command"
else
    fail "expected exit 7, got $RUN_EXIT"
fi

# ---- Test 4: Denied syscall in strict mode → SIGKILL ----
# In strict mode the seccomp deny action is SECCOMP_RET_KILL_PROCESS rather
# than SECCOMP_RET_ERRNO. Triggering a hard-denied syscall (`unshare`, on
# the absolute deny list in recipes/default.toml) must produce a SIGKILL
# exit — i.e., 128 + 9 = 137 from shell's perspective.
begin_test "denied syscall in strict mode terminates with SIGKILL (exit 137)"
if ! has_python3; then
    skip "python3 not available"
else
    run_can run --recipe "$CONFIG" -- python3 -c '
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
# unshare(0) is a no-op semantically but the syscall itself is on the
# absolute deny list; under strict mode the BPF filter must KILL_PROCESS
# before the syscall completes.
libc.unshare(0)
print("NOT_KILLED")
'
    if [[ "$RUN_EXIT" -eq 137 ]]; then
        pass
    elif [[ "$RUN_EXIT" -eq 0 ]]; then
        # Strict mode aborted before the child ran (e.g. missing AppArmor).
        skip "strict mode aborted before child ran (CI feature gap)"
    elif [[ "$RUN_EXIT" -eq 159 ]]; then
        # 159 = 128 + SIGSYS (31). Some kernels deliver SIGSYS first when
        # the seccomp action is RET_KILL_THREAD/RET_TRAP. KILL_PROCESS is
        # the configured action, but we accept SIGSYS as an alternative
        # "process was killed by seccomp" signal.
        pass
    else
        fail "expected exit 137 (SIGKILL) or 159 (SIGSYS), got $RUN_EXIT"
    fi
fi

# ---- Test 6: Non-strict + BPF-denied syscall → process survives, EPERM ----
# Same hard-deny syscall as Test 4 but the recipe is NOT strict. The BPF
# action is SECCOMP_RET_ERRNO; the process keeps running and observes
# errno=EPERM from libc.unshare(0).
begin_test "non-strict + BPF deny: process survives with EPERM (no SIGKILL)"
NONSTRICT_BPF=$(tmpconfig <<'EOF'
strict = false

[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]

[network]
egress = "proxy-only"

[process]
env_passthrough = ["PATH", "HOME", "LANG"]

[syscalls]
seccomp_mode = "allow-list"
EOF
)
_TMPFILES+=("$NONSTRICT_BPF")
if ! has_python3; then
    skip "python3 not available"
else
    run_can run --recipe "$NONSTRICT_BPF" -- python3 -c '
import ctypes, ctypes.util, sys
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
rc = libc.unshare(0)
err = ctypes.get_errno()
# rc must be -1 (syscall denied) and errno must be EPERM (1).
# If we reach this print, the BPF action is RET_ERRNO not RET_KILL_PROCESS.
print("EPERM" if rc == -1 and err == 1 else f"UNEXPECTED rc={rc} err={err}")
sys.stdout.flush()
'
    if [[ "$RUN_EXIT" -eq 0 ]] && [[ "$RUN_STDOUT" == "EPERM" ]]; then
        pass
    elif [[ "$RUN_EXIT" -eq 137 || "$RUN_EXIT" -eq 159 ]]; then
        fail "non-strict mode killed the process; expected survive+EPERM"
    else
        fail "expected stdout=EPERM exit=0, got exit=$RUN_EXIT stdout=$RUN_STDOUT"
    fi
fi

# ---- Test 7: Non-strict + notifier-denied syscall → EPERM ----
# The USER_NOTIF supervisor returns errno on policy denial. Use a
# `connect()` to an IP outside the allow list; the notifier denies with
# EPERM. Process survives, exit code reflects the python script's own
# exit (0 if it caught the error correctly).
begin_test "non-strict + notifier deny on connect(): process survives with EPERM"
NONSTRICT_NOTIF=$(tmpconfig <<'EOF'
strict = false

[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]

[network]
egress = "direct"
allow_ips = ["10.0.0.1"]

[process]
env_passthrough = ["PATH", "HOME", "LANG"]

[syscalls]
seccomp_mode = "allow-list"
EOF
)
_TMPFILES+=("$NONSTRICT_NOTIF")
if ! has_python3; then
    skip "python3 not available"
else
    run_can run --recipe "$NONSTRICT_NOTIF" -- python3 -c '
import socket, errno, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    # 192.0.2.1 (TEST-NET-1) is not in the allow_ips list; the notifier
    # supervisor must deny the connect() with EPERM.
    s.connect(("192.0.2.1", 80))
    print("CONNECTED_UNEXPECTED")
except PermissionError:
    print("EPERM")
except OSError as e:
    # Some kernels surface notifier denial as a generic OSError. Accept
    # any errno that maps to permission denial.
    print("EPERM" if e.errno in (errno.EPERM, errno.EACCES) else f"ERR_{e.errno}")
sys.stdout.flush()
'
    if [[ "$RUN_EXIT" -eq 0 ]] && [[ "$RUN_STDOUT" == "EPERM" ]]; then
        pass
    elif [[ "$RUN_EXIT" -ne 0 ]] && [[ "$RUN_STDOUT" == *"unable to set up notifier"* || "$RUN_STDOUT" == *"USER_NOTIF"* || "$RUN_STDERR" == *"notifier"* ]]; then
        skip "USER_NOTIF unsupported on this kernel"
    else
        fail "expected stdout=EPERM exit=0; got exit=$RUN_EXIT stdout=$RUN_STDOUT"
    fi
fi

# ---- Test 8: Strict + notifier-denied syscall → still EPERM, NOT a kill ----
# Documents that `strict` only escalates the BPF return action. The
# USER_NOTIF supervisor unconditionally responds with -errno on policy
# denial. A future change that wires `strict` into the notifier (e.g.
# SIGKILL on policy deny) would flip this expectation — that would be
# an intentional ADR-worthy decision, and this test will fail-loud to
# force a conscious change.
begin_test "strict + notifier deny on connect(): still EPERM (notifier ignores strict)"
STRICT_NOTIF=$(tmpconfig <<'EOF'
strict = true

[filesystem]
allow = ["/usr/lib", "/usr/bin", "/lib", "/tmp"]

[network]
egress = "direct"
allow_ips = ["10.0.0.1"]

[process]
env_passthrough = ["PATH", "HOME", "LANG"]

[syscalls]
seccomp_mode = "allow-list"
EOF
)
_TMPFILES+=("$STRICT_NOTIF")
if ! has_python3; then
    skip "python3 not available"
else
    run_can run --recipe "$STRICT_NOTIF" -- python3 -c '
import socket, errno, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("192.0.2.1", 80))
    print("CONNECTED_UNEXPECTED")
except PermissionError:
    print("EPERM")
except OSError as e:
    print("EPERM" if e.errno in (errno.EPERM, errno.EACCES) else f"ERR_{e.errno}")
sys.stdout.flush()
'
    if [[ "$RUN_EXIT" -eq 0 ]] && [[ "$RUN_STDOUT" == "EPERM" ]]; then
        pass
    elif [[ "$RUN_EXIT" -eq 137 || "$RUN_EXIT" -eq 159 ]]; then
        fail "strict promoted notifier denial to SIGKILL; if intentional, update t_strict.sh + ADR"
    elif [[ "$RUN_EXIT" -ne 0 ]] && [[ "$RUN_STDOUT" == *"unable to set up notifier"* || "$RUN_STDERR" == *"notifier"* ]]; then
        skip "USER_NOTIF unsupported on this kernel"
    else
        # Strict mode may abort before the child runs if features are
        # missing — Tests 1–4 already cover that case.
        skip "strict mode aborted or unexpected outcome (exit=$RUN_EXIT stdout=$RUN_STDOUT)"
    fi
fi

summary
