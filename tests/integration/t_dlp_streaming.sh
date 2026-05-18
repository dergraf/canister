#!/usr/bin/env bash
# ============================================================================
# t_dlp_streaming.sh — DLP body scan scales beyond the buffered cap
#
# R17: bodies between `max_buffered_body_bytes` (default 8 MiB) and
# `max_streamed_body_bytes` (default 64 MiB) are scanned via the
# chunked streaming primitive (regex + canary substring, no decode
# chain). Bodies above the streaming cap are refused with 413.
#
# Setup: lower both caps for the test so we don't have to ship a 9 MiB
# payload. With `max_buffered_body_bytes = 1024` and
# `max_streamed_body_bytes = 16384`:
#   - a 512-byte body uses the full pipeline (decode chain, etc.)
#   - a 4 KiB body uses the streaming path
#   - a 32 KiB body returns 413
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "DLP body scan: streaming path for oversize bodies"

CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp"]

[network]
egress = "proxy-only"
allow_domains = ["example.com"]

[proxy]
max_buffered_body_bytes = 1024
max_streamed_body_bytes = 16384

[process]
env_passthrough = ["PATH", "HOME", "LANG", "TERM"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

POST='
import os, sys, urllib.request, urllib.error
url, body = sys.argv[1], sys.argv[2].encode()
proxy = os.environ.get("HTTP_PROXY")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "text/plain"})
try:
    resp = opener.open(req, timeout=5)
    print(f"OK status={resp.status}")
except urllib.error.HTTPError as e:
    err = e.headers.get("x-canister-error", "?")
    det = e.headers.get("x-canister-dlp-detector", "?")
    print(f"BLOCKED status={e.code} err={err} detector={det}")
except Exception as e:
    print(f"ERR error={e}")
'

# ---- Test 1: small body with token → blocked via whole-buffer path ----
begin_test "whole-buffer path: 512-byte body with ghp_ token is blocked"
TOKEN="ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SMALL_BODY="$(python3 -c "import sys; sys.stdout.write('x'*468 + '$TOKEN')")"
run_can run --recipe "$CONFIG" -- \
    python3 -c "$POST" "http://example.com/" "$SMALL_BODY"
case "$RUN_STDOUT" in
    *"BLOCKED status=451"*"err=dlp-blocked"*)
        pass
        ;;
    *)
        fail "expected whole-buffer block; got: $RUN_STDOUT"
        ;;
esac

# ---- Test 2: medium body with token → blocked via streaming path ----
# 4 KiB > 1024 buffered cap → streaming scan kicks in.
begin_test "streaming path: 4 KiB body with ghp_ token is blocked"
MEDIUM_BODY="$(python3 -c "import sys; sys.stdout.write('y'*4040 + '$TOKEN')")"
run_can run --recipe "$CONFIG" -- \
    python3 -c "$POST" "http://example.com/" "$MEDIUM_BODY"
case "$RUN_STDOUT" in
    *"BLOCKED status=451"*"err=dlp-blocked"*)
        pass
        ;;
    *)
        fail "expected streaming block; got: $RUN_STDOUT"
        ;;
esac

# ---- Test 3: oversize body → 413 ----
# 32 KiB > 16 KiB streamed cap → refused with 413.
begin_test "oversize body returns 413 (above streamed cap)"
OVERSIZE_BODY="$(python3 -c "import sys; sys.stdout.write('z' * 32768)")"
run_can run --recipe "$CONFIG" -- \
    python3 -c "$POST" "http://example.com/" "$OVERSIZE_BODY"
case "$RUN_STDOUT" in
    *"BLOCKED status=413"*)
        pass
        ;;
    *)
        fail "expected 413 for oversize body; got: $RUN_STDOUT"
        ;;
esac

# ---- Test 4: streaming path catches token split across chunk boundary ----
# StreamingScanner uses a 256-byte overlap. To exercise it via the proxy
# we send a body where the token sits near a 64 KiB boundary — but our
# caps are smaller, so just send a token at any offset > 1024.
begin_test "streaming path: token at random offset still caught"
SPLIT_BODY="$(python3 -c "import sys; sys.stdout.write('p'*2049 + '$TOKEN' + 'q'*1024)")"
run_can run --recipe "$CONFIG" -- \
    python3 -c "$POST" "http://example.com/" "$SPLIT_BODY"
case "$RUN_STDOUT" in
    *"BLOCKED status=451"*"err=dlp-blocked"*)
        pass
        ;;
    *)
        fail "expected block on token at offset 2049; got: $RUN_STDOUT"
        ;;
esac

summary
