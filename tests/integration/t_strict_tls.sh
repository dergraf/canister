#!/usr/bin/env bash
# ============================================================================
# t_strict_tls.sh — the proxy's certificates pass strict X.509 verification
#
# Python 3.13 verifies with OpenSSL's X509_STRICT by default, which refuses a
# CA without key usage and a leaf without an authority key identifier. Set
# explicitly here, so every Python version checks it.
#
# Tests:
#   1. A client verifying strictly, with the CA the sandbox hands it, reaches
#      a declared host through the proxy
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "Strict TLS verification"

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

begin_test "a client verifying strictly reaches a declared host through the proxy"
run_can run --recipe "$RECIPE" -- python3 -c 'import ssl, urllib.request
context = ssl.create_default_context()
context.verify_flags |= ssl.VERIFY_X509_STRICT
try:
    print(urllib.request.urlopen("https://mock.example/x", timeout=10, context=context).read().decode().strip())
except Exception as e:
    print("failed:", e)'
assert_eq "from-the-host" "$RUN_STDOUT"

summary
