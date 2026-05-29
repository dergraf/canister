#!/usr/bin/env bash
# ============================================================================
# t_proxy_domain_filtering.sh — domain allow-listing is enforced by the L7
# proxy, not the seccomp supervisor.
#
# The `[[host]]` table is the egress allow-list. In proxy mode the worker
# has no uplink (see t_egress_structural.sh), so every request flows through
# the proxy, which gates by host/SNI (`OutboundPolicy::allows_host`). A
# request for an unlisted domain is refused at the proxy's CONNECT tunnel.
#
# Runs with `notifier = false`, proving the *proxy* enforces the domain
# allow-list — not the removed USER_NOTIF connect()/sendto() supervisor
# (whose resolve-then-IP-match was both TOCTOU-raceable and DNS-rebinding
# prone).
#
# Needs outbound internet (like the other egress tests).
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
header "Proxy domain filtering (notifier disabled)"

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

# ---- Test 1: allowed domain reaches upstream through the proxy ----
begin_test "allowed domain (example.com) succeeds via the proxy"
run_can run --recipe "$CONFIG" -- bash -c \
    'curl -sS -o /dev/null -w "code=%{http_code}" https://example.com/ 2>/dev/null'
case "$RUN_STDOUT" in
    *code=200*|*code=30*) pass ;;
    *) fail "expected allowed domain to succeed, got: $RUN_STDOUT (stderr: $RUN_STDERR)" ;;
esac

# ---- Test 2: unlisted domain is refused at the proxy ----
# The proxy rejects the CONNECT tunnel for a host not in the allow-list, so
# curl cannot establish the tunnel (exit 56, http_code 000). It must NOT
# return a 2xx.
begin_test "unlisted domain (cloudflare.com) is refused by the proxy"
run_can run --recipe "$CONFIG" -- bash -c \
    'curl -sS -o /dev/null -w "code=%{http_code}" https://cloudflare.com/ 2>/dev/null; echo " exit=$?"'
case "$RUN_STDOUT" in
    *code=200*|*code=204*|*code=30*)
        fail "unlisted domain was NOT blocked: $RUN_STDOUT" ;;
    *)
        # Any non-2xx / curl tunnel failure means the proxy refused it.
        pass ;;
esac

summary
