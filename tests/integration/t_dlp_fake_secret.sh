#!/usr/bin/env bash
# ============================================================================
# t_dlp_fake_secret.sh — [network.dlp] fake_secrets injects a fake into the
# sandbox and never leaks the real host value.
#
# Core invariant of the fake-secret swap: a secret named in fake_secrets is
# replaced inside the sandbox by a pattern-matching *fake*; the real value
# stays with the proxy (outside the sandbox) so a tool that encrypts and
# exfiltrates the secret only ever leaks the useless fake.
#
# This test is hermetic — it makes no real egress. It runs `can up` on a
# project manifest (the trusted home for credential scope; recipe files have
# their fake_secrets stripped by the R16 trust gate) whose command simply
# prints its own GITHUB_TOKEN. We assert the printed value:
#   1. is a valid `ghp_<36>` token (the generated fake fires github_pat), and
#   2. is NOT the real value we exported on the host.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
header "DLP fake_secrets injects fake, hides real value"

PROJ=$(mktemp -d)
cat > "$PROJ/canister.toml" <<'EOF'
[sandbox.faketest]
recipes = ["git"]
command = "printenv GITHUB_TOKEN"

[sandbox.faketest.network]
egress = "proxy"

[sandbox.faketest.network.dlp]
enabled = true
fake_secrets = [{ env = "GITHUB_TOKEN", credential = "github_pat" }]

[[sandbox.faketest.host]]
domain = "api.github.com"
allow_credentials = ["github_pat"]
EOF

# A clearly-real marker that is NOT a valid `ghp_<36 alnum>` token, so the
# fake-extraction regex below can never accidentally capture it.
REAL_TOKEN="ghp_REAL_SECRET_VALUE_MUST_NOT_LEAK_TO_SANDBOX"

begin_test "fake_secrets replaces GITHUB_TOKEN with a fake inside the sandbox"
RUN_EXIT=0
out=$( cd "$PROJ" && GITHUB_TOKEN="$REAL_TOKEN" "$CAN" up faketest 2>/dev/null ) || RUN_EXIT=$?

if printf '%s' "$out" | grep -q "REAL_SECRET_VALUE_MUST_NOT_LEAK"; then
    fail "real GITHUB_TOKEN leaked into the sandbox: $out"
else
    fake=$(printf '%s\n' "$out" | grep -oE 'ghp_[A-Za-z0-9]{36}' | head -n1 || true)
    if [ -n "$fake" ] && [ "$fake" != "$REAL_TOKEN" ]; then
        pass
    else
        fail "expected a ghp_<36> fake token in sandbox output, got: $out"
    fi
fi

rm -rf "$PROJ"
summary
