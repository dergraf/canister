#!/usr/bin/env bash
# ============================================================================
# t_dlp_events.sh — structured DLP event channel
#
# Regression for R13: every DLP block must emit a single-line JSON event
# of the form
#
#   {"event":"dlp_block","host":"…","detector":"…","matched_redacted":"…","timestamp_ms":…}
#
# on stderr. This unlocks SIEM ingestion / orchestrator alerting without
# requiring downstream tools to parse the human-readable `warn!` log.
#
# The check is robust to other log lines on stderr: we grep for the
# specific JSON shape rather than match the whole stream.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "DLP block emits a structured JSON event on stderr"

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

begin_test "dlp_block event line appears on stderr for a header-based block"
run_can run --recipe "$CONFIG" -- python3 -c '
import os, urllib.request, urllib.error
token = "ghp_" + ("A" * 36)
proxy = os.environ.get("HTTP_PROXY")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
req = urllib.request.Request("http://example.com/", headers={"Api-Key": token})
try:
    opener.open(req, timeout=5)
except urllib.error.HTTPError as e:
    print(f"status={e.code}")
'

# We expect at least one line on stderr that:
# - parses as JSON
# - has event="dlp_block"
# - has host containing "example.com"
# - has detector matching "GithubPat"
# - has a redacted matched text that starts with "ghp_" and does NOT
#   contain the raw token bytes.
python3 - "$RUN_STDERR" <<'PYCHECK'
import json, re, sys, os
stderr = sys.argv[1]
found = None
raw_token = "ghp_" + ("A" * 36)
for line in stderr.splitlines():
    # Event lines start with `{` and contain `"event":"dlp_block"`.
    if line.lstrip().startswith("{") and '"dlp_block"' in line:
        try:
            obj = json.loads(line.strip())
        except json.JSONDecodeError:
            continue
        if obj.get("event") == "dlp_block":
            found = obj
            break
if not found:
    print(f"FAIL no dlp_block event found in stderr; stderr was:\n{stderr}")
    sys.exit(1)
checks = []
checks.append(("host", "example.com" in found.get("host", "")))
checks.append(("detector", "github_pat" in found.get("detector", "")))
red = found.get("matched_redacted", "")
checks.append(("redacted_prefix", red.startswith("ghp_")))
checks.append(("redacted_not_full", raw_token not in red))
checks.append(("timestamp", isinstance(found.get("timestamp_ms"), int)))
for name, ok in checks:
    if not ok:
        print(f"FAIL check={name} event={found}")
        sys.exit(1)
print("EVENT_OK")
PYCHECK
PYRC=$?
if [[ "$PYRC" == 0 ]]; then
    pass
else
    fail "dlp_block event check failed"
fi

summary
