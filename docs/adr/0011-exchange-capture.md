# ADR-0011: Exchange Capture

## Status
Accepted

## Date
2026-09-22

## Context

ADR-0010 gives `can` a structured event stream that says *what happened*:
which host was dialled, which contract refused a request, which canary fired.
An orchestrator that evaluates an LLM agent's behavior needs more than that — it
needs *what was said*: the prompts, the tool definitions offered to the model,
the tool calls the model proposed, the arguments it passed, and what the tools
returned.

The proxy already terminates TLS with its dynamic CA and buffers both request and
response bodies for DLP scanning, so the bytes are in hand. What is missing is a
way to emit them, under a flag, without the proxy learning anything about LLM or
MCP protocols — decoding belongs in whatever consumes the stream, not in a
security-critical Rust binary.

Two constraints dominate:

1. **A real secret must never appear in a capture.** The proxy is the one place
   that holds both the fake credential the sandbox carries and the real one it
   swaps in (ADR-0008). A capture feature that leaks the real value into an
   artifact — shipped to a server, stored in a database, attached to a CI job —
   would be worse than no capture at all.
2. **Streamed responses must stay reconstructible.** LLM APIs answer with
   `text/event-stream`; a consumer needs the chunk boundaries and their timing to
   rebuild the message sequence and to measure time-to-first-token.

## Options Considered

### Option 1: Capture in the proxy, after the secret swap
**Description**: Record the exact bytes sent upstream, then redact known secret
values out of the recording.
**Pros**:
- The capture is byte-exact with what the destination received.
**Cons**:
- The real secret is in the buffer at capture time; correctness depends entirely
  on the redactor being exhaustive. One missed encoding (base64 in a body, a
  header the deny-list doesn't know) leaks a production credential.
**Estimated effort**: Low

### Option 2: Capture in the proxy, before the secret swap (chosen)
**Description**: Record the request as the sandbox sent it — carrying the *fake*
credential — and still run the redactor over headers and bodies for both fake and
real values.
**Pros**:
- The real secret is structurally absent from the captured buffer, not merely
  filtered out of it. The redactor becomes defense in depth rather than the only
  defense.
- What the consumer sees is what the agent did, which is the thing under
  evaluation.
**Cons**:
- The captured request differs from the wire bytes by exactly the swapped
  credential. Documented here and in the schema.
**Estimated effort**: Low

### Option 3: Write captures to a side-channel file, not the event stream
**Description**: Keep large bodies out of the event stream; write them to a
directory and reference them by id.
**Pros**: Smaller event lines.
**Cons**: A second transport to secure, clean up and correlate; the consumer
loses the single ordered, hash-chained record. Bodies are already capped.
**Estimated effort**: Medium

## Decision

**Option 2.** New flags, both requiring an event target from ADR-0010:

| Flag | Meaning |
|---|---|
| `--capture-exchanges` | Emit one `exchange` event per HTTP exchange through the proxy, after TLS termination. |
| `--capture-max-bytes <n>` | Per-body cap, default 1 MiB. Bodies above it are truncated with `truncated: true` and the pre-truncation `body_bytes`. |

The `exchange` payload carries the request (method, URL, headers, body), the
response (status, headers, body, chunks) and timings (`started_ms`,
`first_byte_ms`, `ended_ms`). Bodies are base64-encoded.

**Redaction is unconditional and applies to every capture:**

- Header values for `authorization`, `proxy-authorization`, `x-api-key`,
  `api-key`, `cookie` and `set-cookie` are replaced with `[redacted]`.
- Any header value or body byte-range equal to a configured fake secret or its
  real counterpart is replaced with `[redacted]`, in headers and bodies, request
  and response direction.
- The request is captured before the fake→real swap, so the real value is not in
  the buffer to begin with.

**Streaming.** When capture is on, the response body is read frame by frame and
each frame is recorded as `{offset_ms, data_b64}` relative to the request start,
preserving SSE and chunked-transfer boundaries. The concatenation of the chunks
is the body, so a consumer may use either view. With capture off, the response
path is untouched (`Limited::collect`), so default behavior does not change.

**WebSockets** are out of scope: the proxy already refuses the upgrade with 501.
When capture is on, that refusal is recorded as an `exchange` with
`upgrade: "websocket"` and no frames, so a consumer can see the attempt.

**Size and cost.** Capture is off by default. With it on, the memory cost per
in-flight exchange is bounded by `--capture-max-bytes` per direction, on top of
the DLP buffering that already happens.

## Consequences

### Positive
- A consumer can reconstruct the full LLM and tool conversation without the proxy
  knowing any protocol.
- The real secret cannot appear in a capture by construction, and the redactor
  catches the remaining classes (session cookies, unexpected credential headers).
- Time-to-first-byte and inter-chunk timing are measurable per exchange.

### Negative
- Captured request bytes are not byte-identical to what the destination received
  when a secret swap applied. Documented in the schema, and the difference is
  exactly the credential.
- Large exchanges make event lines large. Mitigated by the per-body cap and the
  explicit `truncated` flag.

### Neutral
- Capture reuses the buffers DLP already produces; with DLP disabled and capture
  enabled, the proxy buffers request bodies it would otherwise stream.

## Follow-up Actions
- [ ] Tests proving a real secret can never appear in a captured exchange.
- [ ] Protocol decoders (Anthropic, OpenAI, MCP) stay on the consumer side.
