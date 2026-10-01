# ADR-0018: A Sink for Requests to Undeclared Hosts

## Status
Accepted

## Date
2026-10-01

## Context

Every FQDN a sandbox may reach is declared by a `[[host]]` block (ADR-0007). A request
for any other name is refused at the proxy's connect gate: the `CONNECT` gets a `502`
before any TLS handshake, and the event stream records an `egress_request` with
`method: "CONNECT"`, `decision: "blocked"`, `reason: "policy"`.

That is the right default, and it answers *where* the workload tried to go. It does not
answer *what it was about to send*. No request body ever reaches the DLP and canary
detectors, because there is no request yet — only a `CONNECT` line. For a CI consumer
that runs a workload against planted canaries and asks "did any of this data try to
leave?", the most interesting attempts are exactly the ones aimed at hosts nobody
declared, and those are the ones it learns least about.

`[[host]]` wildcards only cover subdomains of a named domain, so there is no way to
declare "every other host" today, and doing so with a contract would be wrong anyway: a
`[[host]]` is permission to dial.

Two facts about the current code shape the design:

- **Name resolution.** In proxy egress mode the worker's network namespace has no uplink
  at all; the proxy is reached over loopback and is the only process with a route out
  (ADR-0006). Clients send the host *name* in the `CONNECT` line (or the absolute URI for
  plain HTTP) and the proxy resolves it, at dial time, through its own DNS cache. The
  worker resolves nothing — for declared and undeclared hosts alike — so a sink needs no
  DNS support inside the sandbox. It must, however, make sure the *proxy* never resolves
  an undeclared name: a lookup is itself an outbound channel (data can be encoded in the
  labels).
- **The pipeline is already there.** For a declared host the proxy terminates TLS with
  the per-run sandbox CA and runs `handle_inner_request`: contract gate, DNS-entropy
  gate, header/URI scan, body and trailer scan, secret swap, forward, response scan.
  Everything up to the forward is what a sink needs.

## Options Considered

### Option 1: Keep refusing; record the `CONNECT` only
**Description**: No change.
**Pros**:
- Smallest proxy surface: no certificate is minted and no hostile body is parsed for an
  arbitrary name.
**Cons**:
- The question a data-protection review asks — which data was about to leave — has no
  answer for the attempts that matter most.
**Estimated effort**: None

### Option 2: A catch-all `[[host]]` (`domain = "*"`) with a "never forward" flag
**Description**: Let a host block match everything and add a field that answers locally.
**Pros**:
- Reuses the host-block vocabulary.
**Cons**:
- A `[[host]]` is permission to dial (ADR-0007); a catch-all block inverts that meaning
  and makes every audit of the host table ask "is there a `*` somewhere, and does it
  forward?". One missing flag in one recipe turns the sink into open egress.
- Host blocks merge additively across recipes; a catch-all composed into a project
  silently changes the meaning of every other refusal.
**Estimated effort**: Medium

### Option 3: Answer the `CONNECT` itself with a scan of whatever follows, outside the pipeline
**Description**: A dedicated handler that terminates TLS, reads the request and runs the
scanner directly.
**Pros**:
- Fully separate from the forwarding code.
**Cons**:
- Duplicates the request-side scan (headers, URI, decode chain, trailers, streaming scan
  for large bodies, capture). Two copies drift, and the sink would end up scanning less
  than a declared host — the opposite of its purpose.
**Estimated effort**: Medium

### Option 4: An opt-in network mode, `undeclared_hosts = "sink"`, that reuses the scan stages and has no forward (chosen)
**Description**: `[network] undeclared_hosts = "refuse" | "sink"`, default `refuse`. In
`sink` mode a request for an undeclared host *name* is accepted, scanned by the same stage
functions a declared host's request goes through, and answered by the proxy. The sink is a
separate, short function whose only exit is the local answer.
**Pros**:
- Same detectors, same events, same capture as a declared host — no second scanner.
- Off by default; turning it on changes only what happens to requests that are refused
  today.
- The "never forwards" property is structural and reviewable in one file.
**Cons**:
- The proxy now terminates TLS and parses bodies for names nobody declared, which is
  more proxy surface exposed to a hostile workload.
**Estimated effort**: Low

## Decision

**Option 4.**

```toml
[network]
undeclared_hosts = "sink"   # default: "refuse"
```

**What is undeclared.** A request is sunk when its host is a *name* (not an IP literal)
and either the connect gate would refuse it, or the contract gate would refuse it as
`unknown-host` (no matching block under `strict` — the case where no `[[host]]` exists
at all). The `host.canister.local` alias is never sunk. Under `contract_mode = "relaxed"`
an undeclared host is forwarded today, and still is: the sink only ever replaces a
refusal. IP literals stay refused: there is no name to mint a certificate for, and
`reachable_ips` is the explicit, `[unsafe]` way to talk to addresses.

**What the sink does.** In `crates/can-proxy/src/server/sink.rs`:

1. For HTTPS, the `CONNECT` is accepted and TLS is terminated with the sandbox CA, as for
   a declared host. The tunnel is *pinned*: every request on it is sunk, whatever `Host`
   header it carries. Plain HTTP goes straight to step 2.
2. The request runs through the DNS-entropy gate, the header/URI scan and the body and
   trailer scan (or the streaming scan above the buffered cap) — the same functions the
   declared path calls, stopping at the first refusal as it does. Findings produce the
   usual `dlp_block` and `canary_fire` events. The contract gate is skipped (an undeclared
   host has no contract); the secret swap and the forward do not exist in this path.
3. With `--capture-exchanges`, the request is captured like any other.
4. The proxy answers `403`, `x-canister-error: undeclared-host-sink`, with a fixed body.
   The answer is the same whether or not a detector fired, so the workload cannot use
   undeclared hosts to probe which payloads trip which detector.

Nothing in the sink resolves a name, opens a socket or calls the upstream module. That is
the property a reviewer checks, and the tests check it from outside: an upstream reachable
under the undeclared name counts connections and must count zero.

**Events.** `egress_request` gets one new `reason` value, `sink`, with `decision:
"blocked"`:

- once for the accepted `CONNECT` (`method: "CONNECT"`, `path: ""`) — so a client that
  never sends a request on the tunnel (certificate pinning, an aborted handshake) is still
  recorded, exactly as it is when refused;
- once per request on the tunnel, or per plain-HTTP request, with its method and path.

Detector findings keep their own events; `egress_request.reason` stays `sink` even when a
detector fired, because the host being undeclared is why nothing left. In monitor mode
`dlp_block.blocked` is `false` as usual (DLP did not block), while the request is still
sunk. `docs/events-schema-v1.json` documents the new reason value; the schema shape does
not change.

**Requires DLP.** The sink exists to scan. When the DLP pipeline is off (any egress mode
other than `proxy`), `ProxyServer::new` logs a warning and falls back to `refuse`.

**Merge.** Composition never widens behaviour silently: an explicit `refuse` in any layer
wins over `sink`; otherwise any `sink` wins; unset stays unset (resolving to `refuse`).
`refuse` counts as the safer value because it is the narrower proxy behaviour — no
certificate is minted and no hostile body parsed for an arbitrary name — even though both
values send nothing upstream. A recipe or organisation policy that pins `refuse` therefore
cannot be overridden by a later project layer.

**Resolved policy.** `policy_resolved` (ADR-0014) and `can recipe show` render the
resolved value explicitly, `"undeclared_hosts": "refuse"` or `"sink"`, so evidence states
which behaviour governed the run.

## Consequences

### Positive
- A consumer can tell, from the event stream alone, whether a canary or credential was in
  a request aimed at a host nobody declared, and capture can show the request itself.
- The default is unchanged, and `sink` is never less strict than `refuse` about what
  leaves the proxy: in both modes nothing is forwarded and no name is resolved.
- One scanner, one set of detectors: the sink cannot fall behind the declared path.

### Negative
- In `sink` mode the proxy terminates TLS and parses request bodies for arbitrary names
  chosen by the workload — more attack surface in the proxy process. Mitigated by the
  existing body caps (`max_streamed_body_bytes`), by the proxy running in its own network
  namespace, and by the mode being opt-in.
- Each sunk HTTPS attempt yields two `egress_request` events (the `CONNECT` and the
  request) where a refusal yields one, and the `stats` blocked counter counts both.
  Consumers that count attempts should count `CONNECT` events or requests, not both.
- Every policy hash changes once, because the resolved policy now carries
  `undeclared_hosts`. ADR-0014 already accepts that a serialization change does this.
- A workload can now complete a TLS handshake to any name. It learns nothing from that —
  the certificate is from the per-run CA it was handed — but the handshake succeeding is
  observable behaviour that differs from `refuse`.

### Neutral
- IP-literal destinations are refused in both modes.
- A `[[host]]` with a `*.` wildcard is matched by the contract gate but not by the
  connect gate's domain list; such hosts are treated as undeclared by both modes. This
  predates the sink and is tracked separately.

## Follow-up Actions
- [ ] Decide whether the connect gate should accept `*.` wildcard `[[host]]` blocks the
      way the contract gate does.
- [ ] Consider an IP-literal sink for plain HTTP, where no certificate is needed.
