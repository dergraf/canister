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

# ============================================================================
# Matrix extension: cover the rest of the policy axes
# ============================================================================

# ---- Test 4: CIDR allow_ips in proxy-only mode ----
# The proxy's connect_via_cache must agree with NetworkConfig.allow_ips
# CIDR notation. Even in proxy-only mode, this matters when an
# interceptor returns Continue and the proxy dials upstream by IP — the
# proxy's allows_ip check must respect the CIDR.
CIDR_CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp"]

[network]
egress = "proxy-only"
allow_ips = ["10.0.0.0/24"]

[process]
env_passthrough = ["PATH", "HOME"]

[syscalls]
EOF
)
_TMPFILES+=("$CIDR_CONFIG")

begin_test "proxy denies IP outside CIDR in allow_ips"
run_can run --recipe "$CIDR_CONFIG" -- python3 -c '
import os, urllib.request, urllib.error
proxy = os.environ.get("HTTP_PROXY")
handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
opener = urllib.request.build_opener(handler)
# 11.0.0.5 is outside 10.0.0.0/24
req = urllib.request.Request("http://11.0.0.5/")
try:
    resp = opener.open(req, timeout=3)
    print(f"UNEXPECTED status={resp.status}")
except urllib.error.HTTPError as e:
    body = e.read()[:200].decode("utf-8", errors="replace")
    print(f"BLOCKED status={e.code} body={body}")
except Exception as e:
    print(f"ERR error={e}")
'
case "$RUN_STDOUT" in
    *"BLOCKED status=502"*"not allowed by policy"*) pass ;;
    *) fail "expected 502 policy block for 11.0.0.5 outside 10.0.0.0/24, got: $RUN_STDOUT" ;;
esac

begin_test "seccomp denies direct connect even to IP inside CIDR (proxy-only)"
# In proxy-only mode the seccomp filter unconditionally denies non-proxy
# direct egress — allow_ips is for the proxy's outbound policy, not for
# the worker's syscall budget. This pins ADR-0006 semantics.
run_can run --recipe "$CIDR_CONFIG" -- python3 -c '
import errno, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("10.0.0.5", 80))     # inside the CIDR
    print("DIRECT_ALLOWED_UNEXPECTED")
except (PermissionError, OSError) as e:
    code = getattr(e, "errno", None)
    if isinstance(e, PermissionError) or code in (errno.EPERM, errno.EACCES):
        print("DIRECT_DENIED")
    else:
        print(f"DIRECT_ERRNO_{code}")
finally:
    s.close()
'
case "$RUN_STDOUT" in
    *DIRECT_DENIED*) pass ;;
    *) fail "expected DIRECT_DENIED even for in-CIDR IP under proxy-only; got: $RUN_STDOUT" ;;
esac

# ---- Test 5: egress = "none" — both layers deny everything ----
NONE_CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp"]

[network]
egress = "none"

[process]
env_passthrough = ["PATH", "HOME"]

[syscalls]
EOF
)
_TMPFILES+=("$NONE_CONFIG")

begin_test "egress=none: no HTTP_PROXY is exported (no proxy to use)"
run_can run --recipe "$NONE_CONFIG" -- sh -c 'echo "PROXY=${HTTP_PROXY:-unset}"'
# In egress=none mode there should be no proxy started, so HTTP_PROXY
# should be unset OR pointing to a port that nothing listens on. We
# accept "unset" as the contract — egress=none means "no egress at all".
case "$RUN_STDOUT" in
    *"PROXY=unset"*) pass ;;
    *) fail "expected PROXY=unset under egress=none; got: $RUN_STDOUT" ;;
esac

begin_test "egress=none: even loopback non-proxy connect denied"
run_can run --recipe "$NONE_CONFIG" -- python3 -c '
import errno, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    # Any port on 127.0.0.1 — there is no proxy, so this should be denied
    # by the supervisor (no proxy_port to allow).
    s.connect(("127.0.0.1", 12345))
    print("UNEXPECTED_ALLOWED")
except PermissionError:
    print("DENIED")
except OSError as e:
    if e.errno in (errno.EPERM, errno.EACCES):
        print("DENIED")
    elif e.errno == errno.ECONNREFUSED:
        # The connect itself was allowed at the supervisor; just nothing
        # listening. That would be a contract violation under egress=none.
        print("UNEXPECTED_ALLOWED_REFUSED")
    else:
        print(f"OTHER_ERRNO_{e.errno}")
finally:
    s.close()
'
case "$RUN_STDOUT" in
    *DENIED*) pass ;;
    *) fail "expected DENIED under egress=none; got: $RUN_STDOUT" ;;
esac

# ---- Test 6: allow_domains + allow_ips combo ----
# When both are set, the proxy must allow EITHER an allowed domain OR an
# allowed IP literal. allow_domains by itself blocks IP literals (per the
# `enforce_ip_policy` gate in policy.rs); adding allow_ips should
# re-enable just the listed IPs without re-enabling arbitrary literals.
COMBO_CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp"]

[network]
egress = "proxy-only"
allow_domains = ["example.com"]
allow_ips = ["192.0.2.1"]

[process]
env_passthrough = ["PATH", "HOME"]

[syscalls]
EOF
)
_TMPFILES+=("$COMBO_CONFIG")

begin_test "combo: proxy still rejects an unrelated IP literal"
run_can run --recipe "$COMBO_CONFIG" -- python3 -c '
import os, urllib.request, urllib.error
proxy = os.environ.get("HTTP_PROXY")
handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
opener = urllib.request.build_opener(handler)
req = urllib.request.Request("http://198.51.100.1/")    # documentation IP, NOT on allow_ips
try:
    resp = opener.open(req, timeout=3)
    print(f"UNEXPECTED status={resp.status}")
except urllib.error.HTTPError as e:
    body = e.read()[:200].decode("utf-8", errors="replace")
    print(f"BLOCKED status={e.code} body={body}")
except Exception as e:
    print(f"ERR error={e}")
'
case "$RUN_STDOUT" in
    *"BLOCKED status=502"*"not allowed by policy"*) pass ;;
    *) fail "expected combo recipe to still block 198.51.100.1: $RUN_STDOUT" ;;
esac

begin_test "combo: proxy allows the listed IP literal at policy gate"
run_can run --recipe "$COMBO_CONFIG" -- python3 -c '
import os, urllib.request, urllib.error
proxy = os.environ.get("HTTP_PROXY")
handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
opener = urllib.request.build_opener(handler)
# 192.0.2.1 IS on allow_ips. The TCP connect will fail (TEST-NET-1 is
# unreachable) but it must not be rejected at the *policy* gate — we
# look for the absence of the policy-refusal message.
req = urllib.request.Request("http://192.0.2.1/")
try:
    resp = opener.open(req, timeout=3)
    print(f"ALLOWED_OK status={resp.status}")
except urllib.error.HTTPError as e:
    body = e.read()[:200].decode("utf-8", errors="replace")
    print(f"ALLOWED_HTTPERR status={e.code} body={body}")
except Exception as e:
    print(f"ALLOWED_NETERR error={e}")
'
case "$RUN_STDOUT" in
    *"not allowed by policy"*)
        fail "proxy rejected an allow_ips entry at policy gate: $RUN_STDOUT"
        ;;
    *ALLOWED_*) pass ;;
    *) fail "no recognisable outcome: $RUN_STDOUT" ;;
esac

summary
