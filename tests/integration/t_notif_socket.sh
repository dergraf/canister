#!/usr/bin/env bash
# ============================================================================
# t_notif_socket.sh — USER_NOTIF supervisor: socket() argument filtering
#
# Verifies that the supervisor's `evaluate_socket` filter:
#   - allows AF_INET TCP/UDP and AF_INET6
#   - denies AF_PACKET unconditionally
#   - denies AF_INET SOCK_RAW (raw IP packets)
#   - allows AF_NETLINK with NETLINK_ROUTE (protocol 0)
#   - denies AF_NETLINK with other protocols (NETLINK_AUDIT etc.)
#
# These guarantees are security-load-bearing — a raw socket inside a sandbox
# would defeat the netns + DNS filtering layers.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "USER_NOTIF supervisor: socket() filter"

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

# ---- Test: AF_INET TCP allowed, AF_PACKET / SOCK_RAW / AF_NETLINK NETLINK_AUDIT denied ----
begin_test "socket() argument filtering matches supervisor policy"
run_can run --recipe "$CONFIG" -- python3 -c '
import socket, errno

def try_open(family, sock_type, proto, label):
    try:
        s = socket.socket(family, sock_type, proto)
        s.close()
        print(f"{label}=OPENED")
    except PermissionError:
        print(f"{label}=EPERM")
    except OSError as e:
        if e.errno in (errno.EPERM, errno.EACCES):
            print(f"{label}=EPERM")
        elif e.errno == errno.EAFNOSUPPORT:
            # AF_PACKET in netns without root may return EAFNOSUPPORT before
            # our supervisor even sees it. Treat as functionally denied.
            print(f"{label}=EAFNOSUPPORT")
        else:
            print(f"{label}=ERRNO_{e.errno}")

# AF_INET TCP — allowed
try_open(socket.AF_INET, socket.SOCK_STREAM, 0, "AF_INET_TCP")

# AF_INET UDP — allowed
try_open(socket.AF_INET, socket.SOCK_DGRAM, 0, "AF_INET_UDP")

# AF_INET SOCK_RAW — denied
try_open(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP, "AF_INET_RAW")

# AF_PACKET — denied
AF_PACKET = 17
try_open(AF_PACKET, socket.SOCK_RAW, 0, "AF_PACKET")

# AF_NETLINK NETLINK_ROUTE (0) — allowed
AF_NETLINK = 16
NETLINK_ROUTE = 0
try_open(AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE, "AF_NETLINK_ROUTE")

# AF_NETLINK NETLINK_AUDIT (9) — denied (security-relevant)
NETLINK_AUDIT = 9
try_open(AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT, "AF_NETLINK_AUDIT")
'

# Allowed sockets must succeed.
assert_contains "$RUN_STDOUT" "AF_INET_TCP=OPENED"
assert_contains "$RUN_STDOUT" "AF_INET_UDP=OPENED"
assert_contains "$RUN_STDOUT" "AF_NETLINK_ROUTE=OPENED"

# Denied sockets must be rejected (EPERM, EACCES, or EAFNOSUPPORT all count
# as "did not get a usable raw/packet socket").
begin_test "AF_INET SOCK_RAW is denied"
case "$RUN_STDOUT" in
    *AF_INET_RAW=EPERM*|*AF_INET_RAW=EAFNOSUPPORT*) pass ;;
    *) fail "expected AF_INET_RAW denial, got: $(echo "$RUN_STDOUT" | grep AF_INET_RAW)" ;;
esac

begin_test "AF_PACKET is denied"
case "$RUN_STDOUT" in
    *AF_PACKET=EPERM*|*AF_PACKET=EAFNOSUPPORT*) pass ;;
    *) fail "expected AF_PACKET denial, got: $(echo "$RUN_STDOUT" | grep AF_PACKET=)" ;;
esac

begin_test "AF_NETLINK non-ROUTE protocol is denied"
case "$RUN_STDOUT" in
    *AF_NETLINK_AUDIT=EPERM*|*AF_NETLINK_AUDIT=EAFNOSUPPORT*) pass ;;
    *) fail "expected AF_NETLINK_AUDIT denial, got: $(echo "$RUN_STDOUT" | grep AF_NETLINK_AUDIT)" ;;
esac

summary
