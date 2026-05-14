#!/usr/bin/env bash
# ============================================================================
# t_proxy_seccomp_parity.sh — Proxy + seccomp enforcement parity
#
# Given a single recipe with `egress = "proxy-only"` and a domain allow
# list, both enforcement layers must agree on what is and isn't allowed:
#
#   - The L7 proxy must return 502 ("domain not allowed by policy") when
#     the sandboxed worker requests a disallowed domain through it.
#   - The seccomp USER_NOTIF supervisor must return EACCES when the
#     worker bypasses the proxy and tries to dial any non-proxy address
#     directly.
#
# Any drift between these two layers is a policy bypass — fix it.
#
# Allowed-domain success path stays out of scope here (covered by
# t_dns_filtering.sh and the proxy unit tests); this file only asserts
# the deny-path parity.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "Proxy + seccomp enforcement parity"

CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp"]

[network]
egress = "proxy-only"
allow_domains = ["example.com"]

[process]
env_passthrough = ["PATH", "HOME", "LANG", "TERM"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

# ---- Test 1: proxy rejects a disallowed domain ----
# The sandbox auto-starts a proxy on a loopback port and injects
# HTTP_PROXY into the worker's environment. A request to a domain not on
# the allow list must come back as a 502 from the proxy itself (we read
# the body to confirm; status alone would also catch upstream timeouts).
begin_test "proxy returns 502 for disallowed domain"
run_can run --recipe "$CONFIG" -- python3 -c '
import os, socket, sys, urllib.request, urllib.error
proxy = os.environ.get("HTTP_PROXY")
assert proxy, "HTTP_PROXY not set inside sandbox"
print(f"PROXY={proxy}")

handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
opener = urllib.request.build_opener(handler)
req = urllib.request.Request("http://cloudflare.com/")
try:
    resp = opener.open(req, timeout=5)
    body = resp.read()[:200].decode("utf-8", errors="replace")
    print(f"PROXY_RESP status={resp.status} body={body}")
except urllib.error.HTTPError as e:
    body = e.read()[:200].decode("utf-8", errors="replace")
    print(f"PROXY_DENIED status={e.code} body={body}")
except Exception as e:
    print(f"PROXY_ERR error={e}")
'
echo "  stdout: $RUN_STDOUT"
case "$RUN_STDOUT" in
    *"PROXY_DENIED status=502"*)
        # Confirm the body mentions a policy refusal — distinguishes a
        # real policy block from an upstream timeout (which would also be
        # 502 but for the wrong reason).
        case "$RUN_STDOUT" in
            *"not allowed by policy"*) pass ;;
            *) fail "got 502 but body didn't mention policy: $RUN_STDOUT" ;;
        esac
        ;;
    *)
        fail "expected PROXY_DENIED status=502; got: $RUN_STDOUT"
        ;;
esac

# ---- Test 2: seccomp denies direct connect bypassing the proxy ----
# The same recipe must also make the supervisor deny any direct TCP
# connect to a non-proxy address. We pick a routable but unlikely-to-be-
# listening RFC1918 IP — we only need the supervisor's verdict (EACCES),
# not a successful TCP handshake.
begin_test "seccomp denies direct connect (proxy bypass)"
run_can run --recipe "$CONFIG" -- python3 -c '
import errno, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("10.255.255.1", 443))
    print("DIRECT_ALLOWED_UNEXPECTED")
except PermissionError:
    print("DIRECT_DENIED")
except OSError as e:
    if e.errno in (errno.EPERM, errno.EACCES):
        print("DIRECT_DENIED")
    else:
        print(f"DIRECT_ERRNO_{e.errno}")
finally:
    s.close()
'
case "$RUN_STDOUT" in
    *DIRECT_DENIED*) pass ;;
    *) fail "expected DIRECT_DENIED, got: $RUN_STDOUT" ;;
esac

# ---- Test 3: same recipe still lets the proxy talk to the allowed
# domain. Doesn't require the request to succeed end-to-end — we just
# need to see the proxy attempt the connection rather than reject it
# with a policy error. Skipped if external DNS isn't reachable from CI.
begin_test "proxy does NOT reject allowed domain at policy gate"
run_can run --recipe "$CONFIG" -- python3 -c '
import os, urllib.request, urllib.error
proxy = os.environ.get("HTTP_PROXY")
handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
opener = urllib.request.build_opener(handler)
req = urllib.request.Request("http://example.com/")
try:
    resp = opener.open(req, timeout=10)
    print(f"ALLOWED_STATUS={resp.status}")
except urllib.error.HTTPError as e:
    body = e.read()[:200].decode("utf-8", errors="replace")
    print(f"ALLOWED_HTTPERR status={e.code} body={body}")
except Exception as e:
    print(f"ALLOWED_ERR error={e}")
'
# Any of these is fine: a 2xx/3xx, an HTTP error from upstream, or any
# network error from the proxy↔upstream leg. What MUST NOT appear is the
# proxy's own "not allowed by policy" 502.
case "$RUN_STDOUT" in
    *"not allowed by policy"*)
        fail "proxy rejected the allowed domain (policy mismatch): $RUN_STDOUT"
        ;;
    *ALLOWED_STATUS*|*ALLOWED_HTTPERR*|*ALLOWED_ERR*)
        pass
        ;;
    *)
        fail "no recognisable outcome: $RUN_STDOUT"
        ;;
esac

summary
