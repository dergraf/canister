#!/usr/bin/env bash
# ============================================================================
# t_dlp_header.sh — DLP catches credentials in non-`x-*` custom auth headers
#
# Regression for F4 (DLP plan): the original `scan_headers` allow list was
# narrow — `authorization | cookie | proxy-authorization | x-*`. Custom auth
# headers like `Api-Key`, `Private-Token` (GitLab), `Refresh-Token`,
# `Access-Token` were silently skipped, so a GitHub PAT shipped via
# `Api-Key:` to an unauthorized host slipped past every detector.
#
# This file pins each common offender by:
#   1. Putting a recipe in `proxy-only` mode with `allow_domains` covering
#      a benign upstream we never actually expect to reach.
#   2. Issuing requests through the proxy that carry a GitHub PAT in
#      various non-standard header names.
#   3. Asserting each request comes back as HTTP 451 with
#      `x-canister-error: dlp-blocked`.
#
# A passing run also implicitly validates the redaction logic (R4) — the
# raw token must not appear in the proxy's stderr log, but that is
# checked at the unit-test layer (redact::tests).
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "DLP catches secrets in custom auth headers"

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

# Helper: send a request through the proxy with the given header name and
# echo the result in a parser-friendly form. The token is a fake but
# pattern-valid `ghp_` followed by 36 chars — the GithubPat regex fires
# without any real GitHub call.
PYTHON_CLIENT='
import os, sys, urllib.request, urllib.error
header_name, header_value, url = sys.argv[1], sys.argv[2], sys.argv[3]
proxy = os.environ.get("HTTP_PROXY")
assert proxy, "HTTP_PROXY not set"
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
req = urllib.request.Request(url, headers={header_name: header_value})
try:
    resp = opener.open(req, timeout=5)
    print(f"UNEXPECTED status={resp.status}")
except urllib.error.HTTPError as e:
    detector = e.headers.get("x-canister-dlp-detector", "?")
    err_kind = e.headers.get("x-canister-error", "?")
    print(f"BLOCKED status={e.code} err={err_kind} detector={detector}")
except Exception as e:
    print(f"ERR error={e}")
'

run_dlp_check() {
    local header_name="$1"
    local token="ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    begin_test "DLP blocks GithubPat via '${header_name}' header"
    run_can run --recipe "$CONFIG" -- \
        python3 -c "$PYTHON_CLIENT" "$header_name" "$token" "http://example.com/"
    case "$RUN_STDOUT" in
        *"BLOCKED status=451"*"err=dlp-blocked"*)
            pass
            ;;
        *)
            fail "expected 451 dlp-blocked for header ${header_name}; got: $RUN_STDOUT"
            ;;
    esac
}

# Each of these is a documented evasion vector against the old allow list.
for h in "Api-Key" "Apikey" "Auth-Token" "Access-Token" \
         "Refresh-Token" "Private-Token" "Secret-Key"; do
    run_dlp_check "$h"
done

# Sanity: the canonical Authorization header still works (regression guard
# for any future tightening of the allow list that goes too far).
run_dlp_check "Authorization"

summary
