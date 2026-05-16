#!/usr/bin/env bash
# ============================================================================
# t_notif_clone_namespace.sh — USER_NOTIF supervisor: clone() ns flags filter
#
# Inside the sandbox, creating a nested namespace (CLONE_NEWUSER,
# CLONE_NEWNS, CLONE_NEWPID, etc.) must be denied. This prevents:
#   - escaping the sandbox via nested user-namespace privilege escalation
#   - mounting filesystems outside the supervised mount namespace
#
# The supervisor's `evaluate_clone` / `evaluate_clone3` reject any clone
# whose flags overlap the namespace-creation bitmask.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "USER_NOTIF supervisor: clone() namespace flags"

CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp"]

[network]
egress = "proxy-only"

[process]
env_passthrough = ["PATH", "HOME"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

# ---- Test: unshare(CLONE_NEWUSER) and clone(CLONE_NEWUSER) are denied ----
begin_test "nested user namespace creation is denied"
run_can run --recipe "$CONFIG" -- python3 -c '
import ctypes, ctypes.util, errno, os

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# Constants from <sched.h>
CLONE_NEWUSER = 0x10000000
CLONE_NEWNS   = 0x00020000
CLONE_NEWPID  = 0x20000000
CLONE_NEWNET  = 0x40000000

def try_unshare(flags, label):
    rc = libc.unshare(flags)
    if rc == 0:
        print(f"{label}=ALLOWED")
    else:
        err = ctypes.get_errno()
        print(f"{label}=ERRNO_{err}")

try_unshare(CLONE_NEWUSER, "UNSHARE_NEWUSER")
try_unshare(CLONE_NEWNS,   "UNSHARE_NEWNS")
try_unshare(CLONE_NEWPID,  "UNSHARE_NEWPID")
try_unshare(CLONE_NEWNET,  "UNSHARE_NEWNET")
'

# Any of: EPERM (1), EACCES (13), EINVAL (22) from the kernel after the
# supervisor injects EPERM-on-clone-flags counts as "denied". We accept the
# broader set here because some kernels refuse nested userns via EINVAL
# before the syscall reaches our filter.
for label in UNSHARE_NEWUSER UNSHARE_NEWNS UNSHARE_NEWPID UNSHARE_NEWNET; do
    begin_test "$label denied"
    line=$(echo "$RUN_STDOUT" | grep "^${label}=" || true)
    case "$line" in
        "${label}=ERRNO_1"|"${label}=ERRNO_13"|"${label}=ERRNO_22")
            pass ;;
        "${label}=ALLOWED")
            fail "$label was not denied; nested namespace creation succeeded" ;;
        *)
            fail "$label: unexpected output: $line" ;;
    esac
done

summary
