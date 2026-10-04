# ADR-0027: Transparent Egress

## Status
Accepted

## Date
2026-10-04

## Context

Under `egress = "proxy"` the workload's network namespace has no uplink; the proxy is
reached on loopback through `HTTP_PROXY`/`HTTPS_PROXY` (ADR-0006). A client that honours
those variables goes through the contract gate, DLP, the canary detectors, the
undeclared-host sink and capture. A client that does not fails to connect, and no event
says it tried: it never reaches the proxy.

That client is common. The Python MCP SDK starts every stdio MCP server with a minimal
environment (`HOME`, `PATH`, `SHELL`, …), so a fetching MCP server ignores the proxy and
every request it makes fails silently. Many tools and SDKs do not read proxy variables at
all. For a consumer that runs agents to see what they do, the traffic it most needs to
see is the traffic it cannot.

## Options Considered

### Option 1: Stub DNS and transparent listeners in the workload's namespace (chosen)
**Description**: With `[network] transparent = true`, a stub resolver on `127.0.0.1:53`
in the workload's namespace answers every `A` query with `127.0.0.1`, and the proxy also
listens there on 443 and 80. On 443 it reads the TLS ClientHello's SNI before choosing a
certificate and takes the same path a `CONNECT` takes; on 80 it routes plain HTTP by
`Host`.
**Pros**:
- One pipeline: contracts, DLP, canaries, the sink and capture apply unchanged, and the
  events are the ones a proxied request produces.
- The stub resolves nothing upstream, so data in a query name never leaves.
- No packet rewriting, no new privileges outside the sandbox's own namespace.
**Cons**:
- Only ports 443 and 80. A client dialling another port still fails unseen.
- The workload cannot serve on 80 or 443 on loopback itself while it is on.
- A client that ignores the proxy settings often also ignores `SSL_CERT_FILE`
  (Python's `httpx` uses `certifi`'s own bundle), so it rejects the sandbox CA and no
  request is ever made. The attempt is recorded (`reason: client_rejected_ca`, with the
  host from SNI); what it would have sent is not.
- `AAAA` gets no answer, so a client insisting on IPv6 fails.
**Estimated effort**: Medium.

### Option 2: Redirect every outbound connection with nftables
**Description**: `nft` rules in the workload's namespace redirect all TCP to the proxy,
which recovers the original destination with `SO_ORIGINAL_DST`.
**Pros**:
- Every port.
**Cons**:
- Needs nftables (or iptables) and kernel modules inside a user namespace, which varies
  by distribution; the destination is an IP, not a name, so the proxy still needs SNI or
  `Host` to judge it against host contracts.
**Estimated effort**: High.

### Option 3: Set the proxy variables more aggressively
**Description**: Inject them for subprocesses, e.g. via `LD_PRELOAD` or a wrapper.
**Pros**:
- No network change.
**Cons**:
- A process that clears its environment, or never reads the variables, is unaffected;
  `LD_PRELOAD` does not reach static binaries.
**Estimated effort**: Medium.

## Decision

Option 1, opt-in. The proxy binds the three sockets in the workload's namespace before it
moves to its own, as it does for its main listener, after lowering that namespace's
`ip_unprivileged_port_start` to 0 (the namespace is the sandbox's own). If it cannot bind
them, the run stops: transparent egress was asked for, and going without would hide
exactly the traffic it exists to show. The worker's `resolv.conf` names the stub. A
transparent TLS connection without SNI is refused and recorded (`reason: no_sni`); one
whose client aborts the handshake is recorded as `reason: client_rejected_ca`. The
connect gate is shared with `CONNECT`, so a refused or sunk transparent attempt records
the same `egress_request` events. `transparent` is rendered in the resolved policy only
when on; any layer turning it on wins when recipes compose, since it changes what is
seen, not what may leave.

## Consequences

### Positive
- A workload that ignores proxy settings is judged like one that honours them.

### Negative
- Ports other than 80 and 443 are not covered; recorded as a limit, not a guarantee.

### Neutral
- Off by default; a sandbox without it behaves as before.

## Follow-up Actions
- [x] `[network] transparent`, stub resolver, transparent listeners, shared connect gate
- [ ] Scan query names with the canary detectors, so data encoded in a lookup is a finding
