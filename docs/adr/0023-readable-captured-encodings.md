# ADR-0023: Captured Responses in Encodings Any Consumer Can Read

## Status
Accepted

## Date
2026-10-04

## Context

`--capture-exchanges` (ADR-0011) records each HTTP exchange through the proxy as it
crossed the wire, bodies included. Real HTTP clients ask for compression: Python's
`httpx` and `requests`, Node's `fetch` and most SDKs built on them send
`Accept-Encoding: gzip, deflate, br` (and increasingly `zstd`), and servers pick the
best they support. Model APIs answer `br` to such clients.

The capture keeps the compressed bytes, which is right: the event stream records what
happened. A consumer that wants to read the response has to undo the encoding.
`gzip` and `deflate` are in every standard library (zlib), and `zstd` in many. `br`
(Brotli) is not: decoding it needs a native library, in every consumer, in every
language. A consumer without one sees nothing of the responses of exactly the services
it most wants to read.

The proxy is already a man in the middle for declared hosts: it terminates TLS,
rewrites credential headers (ADR-0008) and scans bodies. It can also tell the upstream
which encodings to use.

## Options Considered

### Option 1: Leave it to consumers
**Description**: Every consumer of `exchange` events bundles a Brotli decoder.
**Pros**:
- No change in `can`.
**Cons**:
- A native dependency in every consumer, in every language, for one encoding.
- A consumer that lacks one fails quietly: it reads nothing and may not notice.
**Estimated effort**: None here, repeated in every consumer.

### Option 2: Decode bodies in the proxy before capture
**Description**: The proxy decompresses each captured body and records the decoded
bytes, with the original encoding in the event.
**Pros**:
- Consumers always see plain bytes.
**Cons**:
- Three decompressors in the proxy, which parses hostile input: more attack surface,
  and decompression bombs to guard against (bounded by `--capture-max-bytes`, but
  the decompressor still runs).
- The event no longer records the bytes that crossed the wire, which weakens it as
  evidence.
- Streamed chunks lose their boundaries once decoded as one.
**Estimated effort**: Medium.

### Option 3: Narrow `Accept-Encoding` on forwarded requests (chosen)
**Description**: With `--capture-readable-encodings`, the proxy rewrites each forwarded
request's `Accept-Encoding` to the encodings it offered that a standard library can
decode — `gzip`, `x-gzip`, `deflate`, `identity` — keeping their q-values, and to
`identity` when none of those were offered.
**Pros**:
- No decoder in the proxy; the capture still records the bytes on the wire.
- Small: one header rewrite, next to the credential swap.
- Opt-in, so default traffic is untouched.
**Cons**:
- Changes what the upstream sees: responses may be larger, and a server that only
  supports `br` (none known) answers uncompressed.
- The workload receives the narrower encoding it never asked for. Every encoding kept
  is one the client offered itself, so it can decode the answer.
**Estimated effort**: Low.

## Decision

Option 3. `--capture-readable-encodings` requires `--capture-exchanges`, since there is
nothing to read without a capture. It applies to every request the proxy forwards. The
captured request keeps the client's original `Accept-Encoding`, because it is recorded
before the rewrite (as it is recorded before the credential swap), so the evidence
shows what the workload asked for, and the captured response shows what it got.

Request bodies are not touched: clients rarely compress them, and the DLP scanner reads
request bodies as sent.

## Consequences

### Positive
- A consumer with only zlib can read every captured response from a client that asked
  for `br`.
- No new parser of hostile input in the proxy.

### Negative
- Uncompressed responses are larger. Mitigated by keeping `gzip` whenever the client
  offered it, which every common client does.
- A workload that compares the `Content-Encoding` it receives against what it asked for
  sees a difference. None known; such a workload runs without the flag.

### Neutral
- The resolved policy is unchanged: this is a capture setting, carried with the event
  configuration like `--capture-max-bytes`.

## Follow-up Actions
- [x] `CaptureConfig.readable_encodings`, the CLI flag, the rewrite, unit and proxy tests
- [ ] Revisit if a consumer needs request-body decoding too
