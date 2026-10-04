#!/usr/bin/env bash
# ============================================================================
# t_host_loopback.sh — [unsafe] host_loopback and `loopback:` upstreams
#
# Tests:
#   1. A declared host with a loopback upstream reaches a host service,
#      whichever pasta is installed. With one too old for
#      --map-host-loopback (Ubuntu 24.04's passt, which CI installs), pasta
#      maps the gateway to the host's loopback and the proxy dials that.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "Host loopback upstreams"

WORK=$(mktemp -d)
trap 'kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"; cleanup' EXIT

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
# Answers any request target: the proxy forwards plain HTTP in absolute
# form, which http.server's file handler does not map to a file.
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

RECIPE=$(tmpconfig <<TOML
[network]
egress = "proxy"

[unsafe]
host_loopback = true

[[host]]
domain = "mock.example"
upstream = "loopback:$PORT"
TOML
)
_TMPFILES+=("$RECIPE")

FETCH='import os, urllib.request
print(urllib.request.urlopen("http://mock.example/index.html", timeout=10).read().decode().strip())'

if pasta --help 2>/dev/null | grep -q -- '--map-host-loopback'; then
    MODE="pasta maps its own address"
else
    MODE="old pasta, through the gateway"
fi

begin_test "a loopback upstream reaches a service on the host ($MODE)"
run_can run --recipe "$RECIPE" -- python3 -c "$FETCH"
assert_eq "from-the-host" "$RUN_STDOUT"

summary
