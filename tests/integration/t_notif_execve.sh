#!/usr/bin/env bash
# ============================================================================
# t_notif_execve.sh — USER_NOTIF supervisor: execve()/execveat() filter
#
# When `process.allow_execve` is configured, the supervisor's `evaluate_execve`
# canonicalises the target path and rejects anything not on the allow list.
# This holds for *every* exec call — not just the first one — so it must
# block a process from execing arbitrary binaries mid-run.
#
# Tests:
#   1. Allowed binary execs successfully
#   2. Disallowed binary (mid-process exec, post-startup) gets EACCES/EPERM
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "USER_NOTIF supervisor: execve() allow list"

# Resolve canonical paths via readlink -f. The supervisor uses canonicalised
# paths, so we must put canonical paths on `allow_execve` and `os.execv` the
# same canonical path. Using `os.execvp` with PATH search would try many
# candidates (most of which aren't on the allow list) and trip the filter
# even for "allowed" binaries — that's a test-rig issue, not a sandbox bug.
PYTHON3_CANON=$(readlink -f "$(command -v python3)")
SH_CANON=$(readlink -f /bin/sh)

CONFIG=$(tmpconfig <<EOF
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/bin", "/tmp"]

[network]
egress = "proxy-only"

[process]
env_passthrough = ["PATH", "HOME"]
allow_execve = ["${PYTHON3_CANON}", "${SH_CANON}"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

# ---- Test: allowed binary execs ----
begin_test "allowed binary in allow_execve runs"
run_can run --recipe "$CONFIG" -- python3 -c "
import os
os.execv('${SH_CANON}', ['sh', '-c', 'echo ALLOWED_EXEC_OK'])
"
assert_contains "$RUN_STDOUT" "ALLOWED_EXEC_OK"

# ---- Test: disallowed binary mid-process is denied ----
# `cat` is intentionally absent from allow_execve. Running python first
# (which IS allowed), then having it exec /usr/bin/cat must fail.
begin_test "disallowed binary mid-process exec is denied (EACCES/EPERM)"
run_can run --recipe "$CONFIG" -- python3 -c '
import os, errno
try:
    os.execv("/usr/bin/cat", ["cat", "/etc/hostname"])
    print("EXEC_ALLOWED_UNEXPECTED")
except PermissionError:
    print("EXEC_DENIED")
except OSError as e:
    if e.errno in (errno.EPERM, errno.EACCES):
        print(f"EXEC_DENIED_ERRNO_{e.errno}")
    else:
        print(f"EXEC_ERRNO_{e.errno}")
'
case "$RUN_STDOUT" in
    *EXEC_DENIED*) pass ;;
    *) fail "expected EXEC_DENIED, got: $RUN_STDOUT" ;;
esac

summary
