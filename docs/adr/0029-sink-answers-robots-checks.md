# ADR-0029: The Sink Answers a `robots.txt` Check with 404

## Status
Accepted

## Date
2026-10-06

## Context

The undeclared-host sink (ADR-0018) answers every request locally with a fixed
`403`, after the request has been scanned and recorded. Its purpose is to show
what a workload would have sent to a host it may not reach.

Polite HTTP clients ask for `/robots.txt` before fetching a URL. The MCP fetch
server does this before every fetch, and treats a `403` as "fetching is
forbidden". It then stops without making the request. The sink records the
`robots.txt` check and nothing else, so the request it exists to see, which
carries the data in its URL, is never made.

## Options Considered

### Option 1: Answer a `robots.txt` check with 404 (chosen)
**Description**: A `GET` or `HEAD` for `/robots.txt` gets a `404`, with the
same `x-canister-error: undeclared-host-sink` header and body. RFC 9309 treats
an unavailable `robots.txt` as allowing everything, so the client goes on, and
its next request is sunk and recorded as usual.
**Pros**:
- The request that carries the data reaches the detectors and the capture.
- Nothing leaves: the sink still answers locally and never dials the host.
**Cons**:
- The sink's answer is no longer the same for every request.
**Estimated effort**: Low.

### Option 2: Answer every sunk request with 404
**Description**: Use one status code for everything.
**Pros**:
- A single fixed answer.
**Cons**:
- A `403` tells a client that retries or falls back to stop. A `404` for every
  path invites it to probe more paths, which adds noise to the evidence.
**Estimated effort**: Low.

## Decision

Option 1. The check is the request line only: `GET` or `HEAD`, and a path of
exactly `/robots.txt`. The robots request itself is still scanned and recorded
as an `egress_request` with `reason: sink`.

## Consequences

### Positive
- A sunk attempt by a robots-respecting client shows what it would have sent.

### Negative
- A workload can tell a sunk host from one that forbids everything by its
  `robots.txt` answer. It could already tell that from the header.

### Neutral
- A sandbox without `undeclared_hosts = "sink"` is unaffected.

## Follow-up Actions
- [x] `sink_response` answers a `robots.txt` check with 404
