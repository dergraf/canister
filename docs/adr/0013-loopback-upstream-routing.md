# ADR-0013: Routing a `[[host]]` to a Service on the Host's Loopback

## Status
Accepted

## Date
2026-09-22

## Context

An orchestrator that evaluates an agent replaces the agent's real dependencies with
mocks: a claims API, a document store, a third-party MCP server. The mocks run in the CI
job, on the host's loopback interface, because running them anywhere else adds latency and
widens the sandbox's egress policy.

The agent under test must not notice. It should call
`https://claims.mock.internal/claims/42` exactly as it would call the real service, with
TLS, and the run should still exercise the parts of `can` that matter: the connect gate,
the per-destination contract, DLP scanning, canaries and capture.

`can` already has one mechanism in this shape: `host.canister.local` is a magic name the
sandbox can dial, which the upstream connector rewrites to the in-netns gateway address
that pasta maps to the host's `127.0.0.1`. That mechanism is single-purpose (one name, no
port mapping) and it short-circuits the contract gate, because it is canister-internal
plumbing rather than a destination the user authored a contract for.

## Options Considered

### Option 1: Tell the workload to call `host.canister.local:<port>`
**Description**: Reuse the existing alias; the orchestrator rewrites the agent's
configuration to point at the alias with a per-mock port.
**Pros**:
- No change to `can` at all.
**Cons**:
- The agent's configuration differs between a real run and an evaluated run, so the thing
  being evaluated is not the thing that ships. Host-based routing, virtual hosts, TLS
  names and anything keyed on the hostname behave differently.
- Everything collapses onto one hostname, so per-destination contracts, DLP credential
  scope and canary allow-lists — all keyed by host — lose their meaning.
**Estimated effort**: None (but wrong)

### Option 2: `/etc/hosts` entries inside the sandbox plus a local listener
**Description**: Map the mock names to `127.0.0.1` inside the sandbox's mount namespace
and run the mocks inside the sandbox's network namespace.
**Pros**: The agent sees the real names.
**Cons**: The worker netns deliberately has no uplink and the mocks would have to live
inside the sandbox, where they are exposed to the workload under test (and could be
tampered with by it). It also bypasses the proxy entirely, so the run observes nothing.
**Estimated effort**: Medium

### Option 3: Per-host upstream override in the contract block (chosen)
**Description**: Generalize the `host.canister.local` rewrite into a per-`[[host]]`
routing rule:

```toml
[[host]]
domain = "claims.mock.internal"
upstream = "loopback:4101"
methods = ["GET", "POST"]
```

The workload calls `https://claims.mock.internal/...`; the proxy terminates TLS with its
dynamic CA as it does for any host, runs the contract gate and DLP, and then dials the
host's loopback on port 4101 over plain HTTP.
**Pros**:
- The agent's configuration is unchanged from production.
- The route lives next to the contract for the same host, so "what is this destination,
  what shapes does it accept, and where does it actually go" is one block.
- Every gate keeps working, keyed by the real hostname.
**Cons**:
- One more field in the contract schema.
- The hop from proxy to mock is unencrypted (loopback only).
**Estimated effort**: Low

## Decision

**Option 3.** `[[host]] upstream = "loopback:<port>"`, resolved in
`OutboundPolicy::loopback_upstreams` and applied in the upstream connector:

- The dial target becomes `host_loopback_target:<port>` — the same in-netns gateway
  address `host.canister.local` uses, which pasta maps to the host's `127.0.0.1`.
- TLS to the upstream is skipped for routed hosts: the request arrives over TLS, is
  terminated by the proxy, and the loopback hop is plain HTTP. The `Host` header still
  carries the original name, so a mock can serve several virtual hosts.
- The contract gate, DLP scanning, canaries and exchange capture all run first and are
  unaffected — the route only changes where the request is dialled.
- Requires `[network] allow_host_loopback = true`. A route without it, or a malformed
  `upstream` value, is rejected by `ProxyServer::new` rather than discovered per request:
  a per-request failure would look like an upstream outage, and "my mock never got
  called" is a confusing way to learn about a typo.

`host.canister.local` keeps its existing behavior, including its contract-gate
short-circuit; it is canister-internal plumbing, while a routed `[[host]]` is a
destination the operator authored.

## Consequences

### Positive
- Mocks are addressable by their real names, so an evaluated run exercises the same code
  paths as production.
- Per-destination policy keeps working for mocks, which is what makes the evidence
  meaningful ("this data class reached this destination").
- Mocks stay outside the sandbox, where the workload cannot tamper with them.

### Negative
- Traffic between the proxy and the mock is unencrypted. It never leaves the host's
  loopback, and the sandbox has no route to it.
- A route silently makes a real-looking hostname local. Mitigated by keeping the route in
  the audited `[[host]]` block and by `can recipe show` (and the `policy_resolved` event,
  ADR-0014) rendering the resolved value.

### Neutral
- `OutboundPolicy` gains a small map, built once at startup.

## Follow-up Actions
- [ ] The orchestrator generates the `[[host]]` overlay with the ports its mock servers
      bound to.
- [ ] Consider `upstream = "loopback:<port>/https"` if a mock ever needs TLS.
