# ADR-0028: The Sandbox CA in the Trust Bundles Clients Read Unasked

## Status
Accepted

## Date
2026-10-06

## Context

Under `egress = "proxy"` the proxy terminates TLS with a certificate from the
sandbox's own CA. The workload learns about that CA from `SSL_CERT_FILE` and
`NODE_EXTRA_CA_CERTS`, which point at `/tmp/.canister-ca.crt`.

A client started without that environment does not trust the CA. That is the
same client transparent egress exists for (ADR-0027): the Python MCP SDK starts
every stdio server with `HOME` and `PATH` only. Such a client reaches the proxy,
rejects its certificate and sends nothing. The attempt is recorded
(`client_rejected_ca`); what it would have sent is not. Python's `httpx` and
`requests` read `certifi`'s `cacert.pem` and ignore the system bundle, so even an
environment-aware client of theirs rejects the CA unless it reads
`SSL_CERT_FILE` itself.

Where a client looks without being told is a short, known list: OpenSSL's
compiled-in default bundle, which differs per distribution, and `certifi`'s
bundle inside each Python environment.

## Options Considered

### Option 1: Overlay the known bundles with copies that include the CA (chosen)
**Description**: With `[network] overlay_ca_bundles = true`, the worker
bind-mounts a copy of each known bundle that exists in the sandbox, with the
sandbox CA appended, over the original. It does this after `pivot_root`, while it
still holds the capabilities to mount. The locations are a fixed table in
`can-sandbox`.
**Pros**:
- Covers OpenSSL-based clients (Python's `ssl`, curl, Go, Ruby) and `certifi`
  without any environment.
- The original roots stay, so a client keeps trusting what it trusted before.
- Nothing on the host changes: the mounts live in the sandbox's mount namespace.
**Cons**:
- Clients with compiled-in roots (Node.js, `webpki-roots`) or binary keystores
  (Java) are not covered.
- A Python environment outside the table's locations is not found.
**Estimated effort**: Low.

### Option 2: Search every mounted tree for `cacert.pem`
**Description**: Walk the sandbox's mounts at start and overlay every
`certifi/cacert.pem`.
**Pros**:
- Finds environments wherever they are.
**Cons**:
- Walking a large checkout (`node_modules`, build trees) delays every run.
- What is overlaid becomes hard to predict and to audit.
**Estimated effort**: Low.

### Option 3: Set `SSL_CERT_FILE` for subprocesses that clear their environment
**Description**: Force the variable on by `LD_PRELOAD` or a wrapper.
**Pros**:
- No mounts.
**Cons**:
- Does not reach static binaries. `certifi` users ignore the variable anyway.
**Estimated effort**: Medium.

## Decision

Option 1, opt-in. The table names each location with the clients that read it,
and is the one place to extend. `$CWD` (the working directory) and `$HOME` (the
invoking user's home) expand at run start, and `*` matches within one path
segment. A location that does not exist in the sandbox is skipped. Paths that
resolve to the same file are overlaid once. A bundle that cannot be overlaid is
logged and skipped, and the run continues: a client that then rejects the CA is
still recorded as `client_rejected_ca`. As with `transparent`, any recipe layer
that turns `overlay_ca_bundles` on wins when recipes compose. It is rendered in
the resolved policy only when on.

## Consequences

### Positive
- Combined with `transparent`, a stdio MCP server that starts with no
  environment and uses `httpx` is proxied and judged like any other client.

### Negative
- A workload can see that its bundles differ from the host's. The sandbox's CA
  is already visible to it through `SSL_CERT_FILE`.
- Node.js and Java clients that ignore the environment still reject the CA.

### Neutral
- Off by default. A sandbox without the key behaves as before.

## Follow-up Actions
- [x] `[network] overlay_ca_bundles` and the bundle table
- [ ] Extra locations per recipe, if a project's environment lives outside the table
