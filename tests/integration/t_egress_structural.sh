#!/usr/bin/env bash
# ============================================================================
# t_egress_structural.sh — egress is enforced by the network topology,
# not the seccomp supervisor.
#
# In proxy mode the worker's network namespace has no uplink: pasta attaches
# to the proxy's *own* netns, and the proxy binds its listener inside the
# worker netns. So the worker can only reach 127.0.0.1:proxy_port; any direct
# connect to the outside fails with ENETUNREACH at the kernel/routing layer.
#
# Crucially these tests run with `notifier = false`, so they prove the
# *structural* layer enforces egress — not the (removed) USER_NOTIF
# connect()/sendto()/sendmsg() supervisor.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "Structural egress (proxy netns; notifier disabled)"

CONFIG=$(tmpconfig <<'EOF'
[filesystem]
read = ["/usr", "/lib", "/lib64", "/bin", "/etc"]

[network]
egress = "proxy"

[[host]]
domain = "example.com"

[process]
env_passthrough = ["PATH", "HOME"]

[syscalls]
notifier = false
EOF
)
_TMPFILES+=("$CONFIG")

# ---- Test 1: direct connect to a public IP is blocked structurally ----
# Hermetic: no internet needed — with no route in the worker netns the
# connect fails immediately (ENETUNREACH=101 / EHOSTUNREACH=113), never
# succeeds. errno 101/113 = the routing layer refused; that is the green path.
begin_test "direct connect to a public IP fails (no uplink in worker netns)"
run_can run --recipe "$CONFIG" -- python3 -c '
import socket, errno
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("1.1.1.1", 80))
    print("DIRECT_CONNECT_SUCCEEDED")
except OSError as e:
    if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        print("DIRECT_CONNECT_NO_ROUTE")
    else:
        print(f"DIRECT_CONNECT_ERRNO_{e.errno}")
finally:
    s.close()
'
case "$RUN_STDOUT" in
    *DIRECT_CONNECT_NO_ROUTE*) pass ;;
    *) fail "expected ENETUNREACH/EHOSTUNREACH (no uplink), got: $RUN_STDOUT" ;;
esac

# ---- Test 2: the proxy loopback port IS reachable ----
# The worker can still reach the proxy on 127.0.0.1; a connect there either
# succeeds or is refused (proxy not yet accepting), but must NOT be
# ENETUNREACH — loopback has a route.
begin_test "loopback (proxy port) is reachable in the worker netns"
run_can run --recipe "$CONFIG" -- python3 -c '
import socket, errno, os
port = 0
for k, v in os.environ.items():
    if k.lower() in ("http_proxy", "https_proxy"):
        port = int(v.rsplit(":", 1)[1].strip("/"))
        break
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("127.0.0.1", port or 1))
    print("LOOPBACK_OK")
except OSError as e:
    if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        print("LOOPBACK_NO_ROUTE")
    else:
        # ECONNREFUSED etc. still proves loopback is routable.
        print("LOOPBACK_OK")
finally:
    s.close()
'
case "$RUN_STDOUT" in
    *LOOPBACK_OK*) pass ;;
    *) fail "expected loopback routable, got: $RUN_STDOUT" ;;
esac

# ---- Test 3: HTTPS to an allowed host through the proxy works ----
# Needs outbound internet (like t_dns_filtering / t_network). Proves the
# proxy netns has the uplink and the worker reaches the world only via it.
begin_test "HTTPS to allowed host succeeds via the proxy (notifier off)"
run_can run --recipe "$CONFIG" -- bash -c \
    'curl -sS -o /dev/null -w "HTTP_%{http_code}" https://example.com/ 2>/dev/null'
case "$RUN_STDOUT" in
    *HTTP_200*|*HTTP_30*) pass ;;
    *) fail "expected proxied HTTPS to succeed, got: $RUN_STDOUT (stderr: $RUN_STDERR)" ;;
esac

summary
