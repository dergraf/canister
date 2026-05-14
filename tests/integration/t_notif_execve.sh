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
#
# Both the raw command-v path AND its readlink -f resolution are added to
# the allow list, since the supervisor canonicalises the kernel's reported
# exec path which may already be canonical or may go through symlinks
# depending on how the kernel resolves the binary.
PYTHON3_RAW=$(command -v python3)
PYTHON3_CANON=$(readlink -f "$PYTHON3_RAW")
SH_RAW=/bin/sh
SH_CANON=$(readlink -f "$SH_RAW")

# Diagnostic: print what the test is going to use. Helps debug CI mismatches.
echo "  python3: raw=${PYTHON3_RAW} canonical=${PYTHON3_CANON}"
echo "  sh:      raw=${SH_RAW} canonical=${SH_CANON}"

CONFIG=$(tmpconfig <<EOF
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/bin", "/tmp"]

[network]
egress = "proxy-only"

[process]
env_passthrough = ["PATH", "HOME"]
allow_execve = ["${PYTHON3_RAW}", "${PYTHON3_CANON}", "${SH_RAW}", "${SH_CANON}"]

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
if [[ "$RUN_STDOUT" == *"ALLOWED_EXEC_OK"* ]]; then
    pass
else
    fail "expected ALLOWED_EXEC_OK; exit=$RUN_EXIT stdout=$(echo "$RUN_STDOUT" | head -5 | tr '\n' '|') stderr=$(echo "$RUN_STDERR" | tail -5 | tr '\n' '|')"
fi

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
