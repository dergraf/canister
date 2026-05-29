#!/usr/bin/env bash
# ============================================================================
# t_exec_structural.sh — a restricted exec policy makes writable mounts
# noexec, so the worker cannot drop a new binary and run it.
#
# Runs with `notifier = false`, so the dropped-binary block is proven to come
# from the mount flag (MS_NOEXEC on /tmp, the CWD, and writable binds) — not
# from the USER_NOTIF exec supervisor. Under `exec = "any"` the writable
# mounts stay executable so dev build-and-run workflows keep working.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Structural exec hardening (noexec writable mounts)"

PROBE='cp /bin/true /tmp/x 2>/dev/null || cp /usr/bin/true /tmp/x; chmod +x /tmp/x; /tmp/x && echo DROPPED_RAN || echo DROPPED_BLOCKED_rc=$?'

# ---- Test 1: exec = "any" leaves /tmp executable (dev workflows) ----
ANY=$(tmpconfig <<'EOF'
[filesystem]
read = ["/usr", "/lib", "/lib64", "/bin"]
[process]
exec = "any"
env_passthrough = ["PATH", "HOME"]
[syscalls]
notifier = false
EOF
)
_TMPFILES+=("$ANY")
begin_test "exec=any: a binary dropped in /tmp runs (writable stays exec)"
run_can run --recipe "$ANY" -- /bin/sh -c "$PROBE"
case "$RUN_STDOUT" in
    *DROPPED_RAN*) pass ;;
    *) fail "expected DROPPED_RAN under exec=any, got: $RUN_STDOUT" ;;
esac

# ---- Test 2: restricted exec makes /tmp noexec ----
RESTR=$(tmpconfig <<'EOF'
[filesystem]
read = ["/usr", "/lib", "/lib64", "/bin"]
[process]
exec = ["/bin/sh", "/usr/bin/sh", "/bin/cp", "/usr/bin/cp", "/bin/chmod", "/usr/bin/chmod"]
env_passthrough = ["PATH", "HOME"]
[syscalls]
notifier = false
EOF
)
_TMPFILES+=("$RESTR")
begin_test "exec=[paths]: a binary dropped in /tmp cannot be executed (noexec)"
run_can run --recipe "$RESTR" -- /bin/sh -c "$PROBE"
case "$RUN_STDOUT" in
    *DROPPED_BLOCKED*) pass ;;
    *DROPPED_RAN*) fail "dropped binary RAN under restricted exec — noexec not applied" ;;
    *) fail "unexpected outcome: $RUN_STDOUT" ;;
esac

summary
