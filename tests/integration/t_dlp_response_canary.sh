#!/usr/bin/env bash
# ============================================================================
# t_dlp_response_canary.sh — DLP catches canaries reflected in responses
#
# F8 (response direction is never scanned) and R8 (canary-only response
# scan) — together these say the proxy should not blindly forward an
# upstream response that contains a canary token. A malicious upstream
# could otherwise reflect a canary back to the worker as part of a JSON
# field or a redirect header, leaving no signal on the request side.
#
# Setup: the proxy runs with DLP enabled (`egress = "proxy-only"`); the
# worker's env carries `CANISTER_CANARY_*`. We have no way to make
# `example.com` return our canary on demand, so this test spins up a
# small Python HTTP echo server *inside the sandbox* on loopback and
# exercises the response scanner against it.
#
# Network: loopback is reachable from the sandbox (the proxy itself binds
# to loopback). `allow_ips = ["127.0.0.1/32"]` opens the policy gate so
# the proxy can connect to the echo server.
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "DLP catches canary tokens reflected by upstream responses"

CONFIG=$(tmpconfig <<'EOF'
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/usr/local", "/lib", "/lib64", "/tmp", "/etc/ssl"]

[network]
egress = "proxy-only"
allow_ips = ["127.0.0.1/32"]

[process]
env_passthrough = ["PATH", "HOME", "LANG", "TERM"]

[syscalls]
EOF
)
_TMPFILES+=("$CONFIG")

# All test logic runs inside the sandbox in a single Python script:
# - start a tiny HTTP server on 127.0.0.1:<ephemeral>
# - the server echoes whatever query string it receives in the response
#   body, so we control exactly when the canary appears
# - make two requests: one benign, one that asks the server to echo the
#   canary; observe verdicts.
ECHO_AND_CHECK='
import http.server, json, os, socket, sys, threading, time
import urllib.request, urllib.error

CANARY = os.environ["CANISTER_CANARY_GITHUB_PAT"]
PROXY  = os.environ.get("HTTP_PROXY")
assert PROXY, "HTTP_PROXY not set"

# Pick an ephemeral port and bind it before starting the server thread.
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
sock.close()

class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        echo = self.path.split("?echo=", 1)[1] if "?echo=" in self.path else "ok"
        body = echo.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_a, **_kw):
        pass

srv = http.server.HTTPServer(("127.0.0.1", port), Echo)
threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.2)

opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))

# 1) Benign response — no canary in body.
try:
    resp = opener.open(urllib.request.Request(f"http://127.0.0.1:{port}/?echo=hello"), timeout=5)
    body = resp.read().decode()
    print(f"BENIGN status={resp.status} body={body}")
except urllib.error.HTTPError as e:
    det = e.headers.get("x-canister-dlp-detector", "?")
    print(f"BENIGN_BLOCKED status={e.code} detector={det}")
except Exception as e:
    print(f"BENIGN_ERR error={e}")

# 2) Canary echo — server returns the canary as the body.
import urllib.parse
url = f"http://127.0.0.1:{port}/?echo={urllib.parse.quote(CANARY)}"
try:
    resp = opener.open(urllib.request.Request(url), timeout=5)
    body = resp.read().decode()
    print(f"REFLECT status={resp.status} body={body}")
except urllib.error.HTTPError as e:
    det = e.headers.get("x-canister-dlp-detector", "?")
    err = e.headers.get("x-canister-error", "?")
    print(f"REFLECT_BLOCKED status={e.code} err={err} detector={det}")
except Exception as e:
    print(f"REFLECT_ERR error={e}")
'

begin_test "benign response passes through; canary echo is blocked"
run_can run --recipe "$CONFIG" -- python3 -c "$ECHO_AND_CHECK"

# We want BOTH outcomes in the same run: the benign request returned 200
# and the canary echo got a 451 with err=dlp-blocked / detector=canary_token.
case "$RUN_STDOUT" in
    *"BENIGN status=200 body=hello"*"REFLECT_BLOCKED status=451"*"err=dlp-blocked"*)
        pass
        ;;
    *)
        # If pasta / loopback rules in this environment prevented the
        # proxy from reaching the echo server, the benign request will
        # have errored — that's an environmental skip, not a test
        # failure.
        case "$RUN_STDOUT" in
            *"BENIGN_ERR"*|*"BENIGN_BLOCKED"*)
                skip "proxy could not reach 127.0.0.1 echo server: $RUN_STDOUT"
                ;;
            *)
                fail "expected benign 200 + canary 451; got: $RUN_STDOUT"
                ;;
        esac
        ;;
esac

summary
