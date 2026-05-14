#!/usr/bin/env bash
# ============================================================================
# t_notif_connect.sh — USER_NOTIF supervisor: connect() IP allow list
#
# Exercises the `evaluate_connect` arg-level filter using literal IPs
# (`network.allow_ips`). t_dns_filtering.sh covers domain-based connect
# allowance; this complements it with direct IP-literal connects so we
# verify the supervisor's `restrict_outbound` + `allowed_ips` path
# independently of the DNS-cache codepath.
#
# Tests:
#   1. connect() to allowed IP succeeds (or times out if nothing's listening
#      — the supervisor verdict is what we measure)
#   2. connect() to disallowed IP returns EPERM/EACCES
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_python3
header "USER_NOTIF supervisor: connect() IP allow list"

# 127.0.0.1 is always reachable in the namespace's loopback; 10.255.255.1 is
# a routable but almost-certainly-not-listening RFC1918 address — we don't
# need it to be reachable, only to be denied by the filter before connect()
# can do anything.
CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp"]

[network]
egress = "direct"
allow_ips = ["127.0.0.1"]

[process]
env_passthrough = ["PATH", "HOME"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

begin_test "connect() to allowed IP is not blocked by supervisor"
run_can run --recipe "$CONFIG" -- python3 -c '
import socket, errno
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("127.0.0.1", 1))
    print("CONNECT_ALLOWED_TCP_REFUSED_OR_OK")
except PermissionError:
    print("CONNECT_BLOCKED_BY_FILTER")
except OSError as e:
    if e.errno in (errno.EPERM, errno.EACCES):
        print("CONNECT_BLOCKED_BY_FILTER")
    elif e.errno in (errno.ECONNREFUSED, errno.ETIMEDOUT):
        # The supervisor allowed the syscall; the destination just had no
        # listener. That is the green-path outcome for this test.
        print("CONNECT_ALLOWED_TCP_REFUSED_OR_OK")
    else:
        print(f"CONNECT_ERRNO_{e.errno}")
finally:
    s.close()
'
case "$RUN_STDOUT" in
    *CONNECT_ALLOWED_TCP_REFUSED_OR_OK*) pass ;;
    *) fail "expected allowed connect, got: $RUN_STDOUT" ;;
esac

begin_test "connect() to disallowed IP is denied by supervisor"
run_can run --recipe "$CONFIG" -- python3 -c '
import socket, errno
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("10.255.255.1", 80))
    print("CONNECT_ALLOWED_UNEXPECTED")
except PermissionError:
    print("CONNECT_DENIED")
except OSError as e:
    if e.errno in (errno.EPERM, errno.EACCES):
        print("CONNECT_DENIED")
    else:
        print(f"CONNECT_ERRNO_{e.errno}")
finally:
    s.close()
'
case "$RUN_STDOUT" in
    *CONNECT_DENIED*) pass ;;
    *) fail "expected denial, got: $RUN_STDOUT" ;;
esac

summary
