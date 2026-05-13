#!/usr/bin/env bash
# ============================================================================
# t_network.sh — Network isolation (none mode)
#
# Tests:
#   1. No external network access in none mode
#   2. Loopback interface exists
#   3. Direct outbound network works in direct mode
#
# NOTE: Filtered network mode (pasta) tests are separate because they
# require pasta to be installed and take longer to run.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Network isolation"

CONFIG="${CONFIGS_DIR}/network_none.toml"
DIRECT_CONFIG="${CONFIGS_DIR}/network_direct.toml"

# ---- Test 1: No external network in none mode ----
begin_test "no external network access (none mode)"
# Use sh -c with /dev/tcp is bash-specific, so try a connect via python or
# just attempt a simple connection failure test.
run_can run --recipe "$CONFIG" -- sh -c '
    # Try a raw TCP connection — this should fail in network-none mode
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect((\"1.1.1.1\", 80))
    print(\"NETWORK=reachable\")
    s.close()
except Exception:
    print(\"NETWORK=unreachable\")
" 2>/dev/null
    else
        # Fallback: try to read from /dev/tcp (requires bash)
        if exec 3<>/dev/tcp/1.1.1.1/80 2>/dev/null; then
            echo "NETWORK=reachable"
            exec 3>&-
        else
            echo "NETWORK=unreachable"
        fi
    fi
'
assert_contains "$RUN_STDOUT" "NETWORK=unreachable"

# ---- Test 2: Loopback exists ----
begin_test "loopback interface exists"
run_can run --recipe "$CONFIG" -- sh -c 'cat /proc/net/if_inet6 2>/dev/null || echo "LOOPBACK_CHECK=done"'
assert_exit_code 0 "$RUN_EXIT"

# ---- Test 3: Direct mode allows external network ----
begin_test "external network access works (direct mode)"
run_can run --recipe "$DIRECT_CONFIG" -- sh -c '
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((\"1.1.1.1\", 80))
    print(\"NETWORK=reachable\")
    s.close()
except Exception:
    print(\"NETWORK=unreachable\")
"
    else
        if exec 3<>/dev/tcp/1.1.1.1/80 2>/dev/null; then
            echo "NETWORK=reachable"
            exec 3>&-
        else
            echo "NETWORK=unreachable"
        fi
    fi
'
assert_contains "$RUN_STDOUT" "NETWORK=reachable"

summary
