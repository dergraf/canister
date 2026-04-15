#!/usr/bin/env bash
# ============================================================================
# t_dns_filtering.sh — DNS-based domain filtering (pasta + seccomp notifier)
#
# Tests:
#   1. DNS resolution works inside the sandbox (dig/nslookup equivalent)
#   2. Outbound connection to allowed domain succeeds
#   3. Outbound connection to denied domain is blocked
#   4. Connected-socket DNS pattern (Erlang-style) works
#   5. Diagnostic: network namespace routing to DNS server
#
# Requires: pasta, python3
# ============================================================================

source "$(dirname "$0")/lib.sh"
require_user_namespaces
require_pasta
require_python3
header "DNS-based domain filtering"

CONFIG="${CONFIGS_DIR}/dns_filtered.toml"

# ---- Test 1: Diagnostic — network interfaces and routing inside sandbox ----
begin_test "diagnostic: network interfaces and routes inside sandbox"
run_can --verbose run --recipe "$CONFIG" -- sh -c '
    echo "=== INTERFACES ==="
    ip addr 2>/dev/null || ifconfig 2>/dev/null || cat /proc/net/if_inet6 2>/dev/null || echo "NO_IP_TOOLS"
    echo "=== ROUTES ==="
    ip route 2>/dev/null || route -n 2>/dev/null || echo "NO_ROUTE_TOOLS"
    echo "=== RESOLV.CONF ==="
    cat /etc/resolv.conf 2>/dev/null || echo "NO_RESOLV_CONF"
    echo "=== DONE ==="
'
# This test is purely diagnostic — just print the output.
echo "  stdout: $(echo "$RUN_STDOUT" | head -30)"
echo "  stderr (last 20 lines): $(echo "$RUN_STDERR" | tail -20)"
assert_exit_code 0 "$RUN_EXIT"

# ---- Test 2: DNS resolution via raw UDP to sandbox DNS server ----
begin_test "DNS resolution via raw UDP to sandbox DNS server"
run_can --verbose run --recipe "$CONFIG" -- python3 -c "
import re, socket, struct, sys

# Discover the DNS server from the sandbox's resolv.conf (set by pasta).
dns_server = None
try:
    with open('/etc/resolv.conf') as f:
        for line in f:
            m = re.match(r'nameserver\s+(\S+)', line)
            if m:
                dns_server = m.group(1)
                break
except Exception:
    pass
if not dns_server:
    print('DNS_FAIL reason=no_nameserver_in_resolv_conf')
    sys.exit(1)
print(f'DNS_SERVER={dns_server}')

def dns_query(domain, server, port=53, qtype=1):
    \"\"\"Send a raw DNS A query and return parsed IPs.\"\"\"
    # Build query packet
    # Header: ID=0xBEEF, RD=1, QDCOUNT=1
    packet = struct.pack('>HHHHHH', 0xBEEF, 0x0100, 1, 0, 0, 0)
    # Encode domain
    for label in domain.split('.'):
        packet += bytes([len(label)]) + label.encode()
    packet += b'\x00'  # root
    packet += struct.pack('>HH', qtype, 1)  # QTYPE, QCLASS=IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(packet, (server, port))
        resp, _ = sock.recvfrom(512)
    except socket.timeout:
        print(f'DNS_TIMEOUT domain={domain} server={server}')
        return []
    except Exception as e:
        print(f'DNS_ERROR domain={domain} server={server} error={e}')
        return []
    finally:
        sock.close()

    if len(resp) < 12:
        print(f'DNS_SHORT domain={domain}')
        return []

    # Parse header
    tid, flags, qdcount, ancount = struct.unpack('>HHHH', resp[:8])
    rcode = flags & 0xF
    if rcode != 0:
        print(f'DNS_RCODE domain={domain} rcode={rcode}')
        return []

    # Skip question section
    pos = 12
    for _ in range(qdcount):
        while pos < len(resp):
            l = resp[pos]
            if l == 0:
                pos += 1
                break
            if l & 0xC0 == 0xC0:
                pos += 2
                break
            pos += 1 + l
        pos += 4  # QTYPE + QCLASS

    # Parse answers
    ips = []
    for _ in range(ancount):
        if pos >= len(resp):
            break
        # Skip name
        while pos < len(resp):
            l = resp[pos]
            if l == 0:
                pos += 1
                break
            if l & 0xC0 == 0xC0:
                pos += 2
                break
            pos += 1 + l
        if pos + 10 > len(resp):
            break
        rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', resp[pos:pos+10])
        pos += 10
        if rtype == 1 and rdlen == 4:
            ip = '.'.join(str(b) for b in resp[pos:pos+4])
            ips.append(ip)
        pos += rdlen

    return ips

# Test DNS resolution to the sandbox's nameserver
ips = dns_query('example.com', dns_server)
if ips:
    print(f'DNS_OK domain=example.com ips={ips}')
else:
    print('DNS_FAIL domain=example.com')
"
echo "  stdout: $RUN_STDOUT"
echo "  stderr (last 20 lines): $(echo "$RUN_STDERR" | tail -20)"
assert_contains "$RUN_STDOUT" "DNS_OK"

# ---- Test 3: TCP connection to allowed domain ----
begin_test "TCP connection to allowed domain (example.com:80)"
run_can --verbose run --recipe "$CONFIG" -- python3 -c "
import socket, sys

try:
    # Resolve first via DNS
    addrs = socket.getaddrinfo('example.com', 80, socket.AF_INET, socket.SOCK_STREAM)
    if not addrs:
        print('GETADDRINFO_EMPTY domain=example.com')
        sys.exit(1)

    ip = addrs[0][4][0]
    print(f'RESOLVED domain=example.com ip={ip}')

    # Connect
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((ip, 80))
    s.sendall(b'HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n')
    resp = s.recv(256).decode(errors='replace')
    s.close()
    if 'HTTP' in resp:
        print('CONNECT_OK domain=example.com')
    else:
        print(f'CONNECT_UNEXPECTED domain=example.com resp={resp[:80]}')
except Exception as e:
    print(f'CONNECT_FAIL domain=example.com error={e}')
"
echo "  stdout: $RUN_STDOUT"
echo "  stderr (last 20 lines): $(echo "$RUN_STDERR" | tail -20)"
assert_contains "$RUN_STDOUT" "CONNECT_OK"

# ---- Test 4: TCP connection to denied domain is blocked ----
begin_test "TCP connection to denied domain (cloudflare.com) is blocked"
run_can --verbose run --recipe "$CONFIG" -- python3 -c "
import socket, sys

# Try to resolve a domain NOT in the allowlist.
# The DNS query should be allowed (it goes to the pasta DNS forwarder on port 53)
# but the resulting connect() should be blocked.
try:
    addrs = socket.getaddrinfo('cloudflare.com', 80, socket.AF_INET, socket.SOCK_STREAM)
    if not addrs:
        print('GETADDRINFO_EMPTY domain=cloudflare.com')
        sys.exit(0)  # acceptable

    ip = addrs[0][4][0]
    print(f'RESOLVED domain=cloudflare.com ip={ip}')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((ip, 80))
    s.sendall(b'HEAD / HTTP/1.0\r\nHost: cloudflare.com\r\n\r\n')
    resp = s.recv(256).decode(errors='replace')
    s.close()
    print('CONNECT_OK domain=cloudflare.com')  # This should NOT happen
except PermissionError:
    print('CONNECT_DENIED domain=cloudflare.com')  # Expected: EACCES
except OSError as e:
    if e.errno == 13:  # EACCES
        print('CONNECT_DENIED domain=cloudflare.com')
    else:
        print(f'CONNECT_ERROR domain=cloudflare.com error={e}')
except Exception as e:
    print(f'CONNECT_ERROR domain=cloudflare.com error={e}')
"
echo "  stdout: $RUN_STDOUT"
echo "  stderr (last 20 lines): $(echo "$RUN_STDERR" | tail -20)"
assert_contains "$RUN_STDOUT" "CONNECT_DENIED"

# ---- Test 5: Erlang-style connected-socket DNS pattern ----
begin_test "connected-socket DNS (Erlang pattern): connect(dns_server) then sendto(NULL)"
run_can --verbose run --recipe "$CONFIG" -- python3 -c "
import re, socket, struct, sys

# Replicate the Erlang BEAM pattern:
# 1. connect(fd, dns_server:53)
# 2. sendto(fd, dns_query, 0, NULL, 0)  — dest is NULL because socket is connected
# 3. recv response
# 4. connect to resolved IP

# Discover the DNS server from the sandbox's resolv.conf (set by pasta).
dns_server = None
try:
    with open('/etc/resolv.conf') as f:
        for line in f:
            m = re.match(r'nameserver\s+(\S+)', line)
            if m:
                dns_server = m.group(1)
                break
except Exception:
    pass
if not dns_server:
    print('DNS_FAIL reason=no_nameserver_in_resolv_conf')
    sys.exit(1)
print(f'DNS_SERVER={dns_server}')

# Step 1: Create a UDP socket and connect() to DNS server
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
try:
    sock.connect((dns_server, 53))
    print(f'CONNECT_DNS_OK server={dns_server}')
except Exception as e:
    print(f'CONNECT_DNS_FAIL server={dns_server} error={e}')
    sys.exit(1)

# Step 2: Build a DNS A query for example.com
packet = struct.pack('>HHHHHH', 0xDEAD, 0x0100, 1, 0, 0, 0)
for label in 'example.com'.split('.'):
    packet += bytes([len(label)]) + label.encode()
packet += b'\x00'
packet += struct.pack('>HH', 1, 1)  # A record, IN class

# Step 3: Send via send() (equivalent to sendto with NULL addr on connected socket)
try:
    sock.send(packet)
    print('SEND_DNS_OK')
except Exception as e:
    print(f'SEND_DNS_FAIL error={e}')
    sock.close()
    sys.exit(1)

# Step 4: Receive response
try:
    resp = sock.recv(512)
    print(f'RECV_DNS_OK len={len(resp)}')
except socket.timeout:
    print('RECV_DNS_TIMEOUT')
    sock.close()
    sys.exit(1)
except Exception as e:
    print(f'RECV_DNS_FAIL error={e}')
    sock.close()
    sys.exit(1)
sock.close()

# Step 5: Parse the DNS response
if len(resp) < 12:
    print('DNS_SHORT')
    sys.exit(1)

tid, flags, qdcount, ancount = struct.unpack('>HHHH', resp[:8])
rcode = flags & 0xF
if rcode != 0:
    print(f'DNS_RCODE rcode={rcode}')
    sys.exit(1)

# Skip question
pos = 12
for _ in range(qdcount):
    while pos < len(resp):
        l = resp[pos]
        if l == 0:
            pos += 1; break
        if l & 0xC0 == 0xC0:
            pos += 2; break
        pos += 1 + l
    pos += 4

# Parse answers
ips = []
for _ in range(ancount):
    if pos >= len(resp): break
    while pos < len(resp):
        l = resp[pos]
        if l == 0:
            pos += 1; break
        if l & 0xC0 == 0xC0:
            pos += 2; break
        pos += 1 + l
    if pos + 10 > len(resp): break
    rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', resp[pos:pos+10])
    pos += 10
    if rtype == 1 and rdlen == 4:
        ips.append('.'.join(str(b) for b in resp[pos:pos+4]))
    pos += rdlen

if ips:
    print(f'CONNECTED_DNS_OK domain=example.com ips={ips}')
    # Step 6: Try to connect to the resolved IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ips[0], 80))
        s.sendall(b'HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n')
        resp = s.recv(256).decode(errors='replace')
        s.close()
        if 'HTTP' in resp:
            print('CONNECT_RESOLVED_OK')
        else:
            print(f'CONNECT_RESOLVED_UNEXPECTED resp={resp[:80]}')
    except Exception as e:
        print(f'CONNECT_RESOLVED_FAIL error={e}')
else:
    print('CONNECTED_DNS_FAIL no_ips')
"
echo "  stdout: $RUN_STDOUT"
echo "  stderr (last 20 lines): $(echo "$RUN_STDERR" | tail -20)"
assert_contains "$RUN_STDOUT" "CONNECTED_DNS_OK"

# ---- Test 6: Supervisor-side DNS resolution diagnostic ----
# This tests what the supervisor sees. The key question: can the supervisor
# process (which calls resolve_and_add) actually reach the DNS server?
# We test this indirectly: if the dynamic allowlist is populated, the
# connect() to the resolved IP will succeed.
begin_test "supervisor dynamic allowlist populated (end-to-end)"
run_can --verbose run --recipe "$CONFIG" -- python3 -c "
import socket, struct, sys, time

# Use the standard getaddrinfo pattern (which goes through glibc resolver
# reading /etc/resolv.conf in the sandbox). This will trigger:
# 1. Worker calls sendto() to DNS server on port 53
# 2. Seccomp notifier intercepts -> supervisor inspects DNS query
# 3. Supervisor calls resolve_and_add() -> direct UDP to upstream DNS
# 4. Resolved IPs added to dynamic allowlist
# 5. Worker's sendto is allowed, gets DNS response
# 6. Worker calls connect() to resolved IP -> allowed by dynamic allowlist
try:
    addrs = socket.getaddrinfo('example.com', 80, socket.AF_INET, socket.SOCK_STREAM)
    if addrs:
        ip = addrs[0][4][0]
        print(f'RESOLVED ip={ip}')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((ip, 80))
        s.sendall(b'HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n')
        resp = s.recv(256).decode(errors='replace')
        s.close()
        if 'HTTP' in resp:
            print('E2E_OK')
        else:
            print(f'E2E_UNEXPECTED resp={resp[:80]}')
    else:
        print('E2E_FAIL getaddrinfo_empty')
except Exception as e:
    print(f'E2E_FAIL error={e}')
"
echo "  stdout: $RUN_STDOUT"
echo "  stderr (last 20 lines): $(echo "$RUN_STDERR" | tail -20)"
assert_contains "$RUN_STDOUT" "E2E_OK"

summary
