#!/usr/bin/env bash
# ============================================================================
# t_namespace_escape.sh — issue #4 regression: namespace-creation escapes
# are refused, with no TOCTOU window.
#
# Namespace creation from inside the sandbox must always fail:
#   - `unshare(CLONE_NEW*)` is denied by the static baseline BPF (deny list).
#   - `clone(flags)` with any namespace flag is denied by the static notifier
#     prelude (register-decidable: flags are in seccomp_data.args[0]).
#   - `clone3(...)` returns ENOSYS unconditionally — its flags live behind a
#     pointer that BPF cannot read, so rather than inspect that memory (the
#     original issue #4 TOCTOU: a second CLONE_VM thread rewrites the
#     clone_args struct in the check-to-execute window) the kernel refuses
#     clone3 outright, forcing libc to fall back to the register-filtered
#     clone(). There is therefore no memory-inspection window to race.
#
# This runs with the default policy (notifier on) AND is robust to the
# notifier being unsupported — the clone/clone3 gates are static BPF.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "Namespace-escape regression (issue #4)"

CONFIG=$(tmpconfig <<'EOF'
[filesystem]
read = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp"]

[network]
egress = "proxy"

[process]
env_passthrough = ["PATH", "HOME"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

# ---- unshare(CLONE_NEW*) denied ----
begin_test "unshare(CLONE_NEWUSER/NEWNS/NEWPID/NEWNET) denied"
run_can run --recipe "$CONFIG" -- python3 -c '
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
flags = {"NEWUSER":0x10000000,"NEWNS":0x00020000,"NEWPID":0x20000000,"NEWNET":0x40000000}
for name, f in flags.items():
    rc = libc.unshare(f)
    print("UNSHARE_%s=%s" % (name, "ALLOWED" if rc == 0 else "DENIED"))
'
if echo "$RUN_STDOUT" | grep -q "ALLOWED"; then
    fail "a namespace unshare was ALLOWED: $RUN_STDOUT"
else
    pass
fi

# ---- clone(CLONE_NEWUSER) denied (static BPF, register flags) ----
begin_test "clone(CLONE_NEWUSER) denied"
run_can run --recipe "$CONFIG" -- python3 -c '
import ctypes, ctypes.util, errno
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
NR_clone = 56  # x86_64
CLONE_NEWUSER = 0x10000000
# raw clone(flags, stack=0, ...): the BPF prelude denies the ns flag with
# EPERM before the call has any effect.
rc = libc.syscall(NR_clone, CLONE_NEWUSER, 0, 0, 0, 0)
e = ctypes.get_errno()
print("CLONE_RC=%d ERRNO=%d" % (rc, e))
'
case "$RUN_STDOUT" in
    *"CLONE_RC=-1"*) pass ;;
    *) fail "clone(CLONE_NEWUSER) was not denied: $RUN_STDOUT" ;;
esac

# ---- clone3(CLONE_NEWUSER) refused — even from a multithreaded process ----
# The original PoC raced a CLONE_VM sibling thread against the supervisor's
# read of clone_args. clone3 now returns ENOSYS without reading the struct,
# so the race cannot exist. We still spawn threads to mirror the PoC shape.
begin_test "clone3(CLONE_NEWUSER) refused (no TOCTOU window), multithreaded"
run_can run --recipe "$CONFIG" -- python3 -c '
import ctypes, ctypes.util, errno, struct, threading, time
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
NR_clone3 = 435  # x86_64
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID  = 0x20000000

stop = False
def churn():
    while not stop:
        pass
threads = [threading.Thread(target=churn) for _ in range(2)]
for t in threads: t.start()
time.sleep(0.05)

# struct clone_args (kernel): 8 x u64 = 64 bytes is enough for flags-only.
# flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls
args = struct.pack("QQQQQQQQ", CLONE_NEWUSER | CLONE_NEWPID, 0, 0, 0, 0, 0, 0, 0)
buf = ctypes.create_string_buffer(args, len(args))
rc = libc.syscall(NR_clone3, ctypes.byref(buf), len(args))
e = ctypes.get_errno()
stop = True
for t in threads: t.join()

if rc == 0:
    print("CLONE3_ESCAPED")            # child returned here = escape
elif rc > 0:
    print("CLONE3_FORKED_rc=%d" % rc)  # parent got a child pid = escape
else:
    print("CLONE3_REFUSED errno=%d" % e)
'
case "$RUN_STDOUT" in
    *CLONE3_REFUSED*) pass ;;
    *CLONE3_ESCAPED*|*CLONE3_FORKED*) fail "clone3 namespace escape succeeded: $RUN_STDOUT" ;;
    *) fail "unexpected clone3 outcome: $RUN_STDOUT" ;;
esac

# ---- Confinement persists across execve (why the exec-path TOCTOU is harmless) ----
# The residual exec-path race (eval_proc.rs) can at most run a *different*
# already-present binary. This proves that buys nothing: after an exec CHAIN
# (sh -> exec python3), the re-exec'd process is STILL denied namespace
# creation and STILL has no network uplink. No privilege/reach is gained by
# exec, so substituting the binary is a policy bypass, not an escape.
require_python3
begin_test "confinement (no namespaces, no uplink) survives a child execve"
run_can run --recipe "$CONFIG" -- /bin/sh -c 'exec python3 -c "
import ctypes, ctypes.util, errno, socket
libc = ctypes.CDLL(ctypes.util.find_library(\"c\"), use_errno=True)
ns = libc.unshare(0x10000000)  # CLONE_NEWUSER
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3)
try:
    s.connect((\"1.1.1.1\", 80)); net = \"REACHED\"
except OSError as e:
    net = \"BLOCKED\" if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EPERM, errno.EACCES) else \"ERRNO_%d\" % e.errno
finally:
    s.close()
print(\"NS=%s NET=%s\" % (\"DENIED\" if ns != 0 else \"CREATED\", net))
"'
case "$RUN_STDOUT" in
    *"NS=DENIED NET=BLOCKED"*) pass ;;
    *) fail "confinement did not survive execve: $RUN_STDOUT" ;;
esac

summary
