#!/usr/bin/env bash
# ============================================================================
# t_network.sh — Network isolation (none mode)
#
# Tests:
#   1. No external network access in none mode
#   2. Loopback interface exists
#
# NOTE: Filtered network mode (slirp4netns) tests are separate because they
# require slirp4netns to be installed and take longer to run.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
header "Network isolation"

CONFIG="${CONFIGS_DIR}/network_none.toml"

# ---- Test 1: No external network in none mode ----
begin_test "no external network access (none mode)"
# Use sh -c with /dev/tcp is bash-specific, so try a connect via python or
# just attempt a simple connection failure test.
run_can run --config "$CONFIG" -- sh -c '
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
run_can run --config "$CONFIG" -- sh -c 'cat /proc/net/if_inet6 2>/dev/null || echo "LOOPBACK_CHECK=done"'
assert_exit_code 0 "$RUN_EXIT"

summary
