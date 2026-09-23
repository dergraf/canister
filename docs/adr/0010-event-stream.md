# ADR-0010: Structured Event Stream (schema v1)

## Status
Accepted

## Date
2026-09-22

## Context

`can` already emits two structured events on stderr — `dlp_block` and
`canary_fire` (the latter with a tamper-evident hash chain, R18). Everything
else a run does (which hosts were dialled, which contracts refused a request,
what the worker exec'd, how the run ended) is only visible as human-readable
`tracing` output.

CI harnesses that drive `can` need a machine-readable record of an entire run:
one an external observer can consume live, correlate across repeated runs, and
verify for completeness. Parsing `tracing` lines is not a contract anybody should
depend on, and asking every such consumer to invent its own is worse.

Constraints:

- **stdout/stderr are taken.** The sandboxed command owns stdout/stderr, and the
  consumer (an Erlang/Elixir runner) can only see a child's stdout/stderr through
  a port. A separate channel is needed.
- **`can` is multi-process.** The CLI process forks a *proxy process* (which
  joins the worker's user and network namespaces) and, when argument-level
  filtering is on, a *supervisor process* running as PID 1 in the worker's PID
  namespace. All three observe events worth emitting, and they cannot share
  in-memory state after the fork.
- **The sandboxed workload must not be able to forge events.** The agent under
  test is the thing being observed; it must never reach the event channel.
- **Default behavior must not change.** No flag, no new output.

## Options Considered

### Option 1: One connection shared by all processes
**Description**: The CLI connects once before forking; children inherit the
connected fd and write to it.
**Pros**:
- A single sequence number and a single hash chain for the whole run.
- One connection for the consumer to accept.
**Cons**:
- Concurrent `write(2)` calls from *different processes* to one `SOCK_STREAM`
  socket are not atomic; a large `exchange` event (R2, up to ~1 MiB) can
  interleave with another process's line and corrupt both.
- Making it safe requires funnelling every child's events through a pipe to a
  serializing thread in the CLI — more moving parts in the security-critical
  fork path, and the funnel becomes a place where events are silently lost.
**Estimated effort**: Medium

### Option 2: One connection per emitting process, each its own chain (chosen)
**Description**: Each process opens its own connection to the runner's listening
socket and owns an independent `(stream, seq)` space and hash chain. The
envelope carries a `stream` field (`cli`, `proxy`, `supervisor`).
**Pros**:
- No cross-process write interleaving by construction: one writer per connection,
  serialized inside the process by a mutex.
- Truncation and reordering remain detectable *per stream*, which is what the
  hash chain actually protects.
- The fork path gains one `connect(2)` and nothing else.
**Cons**:
- The consumer merges several streams (by `ts_ms`, with `seq` ordering within a
  stream) instead of reading one totally ordered log.
- "Did I get everything?" is answered per stream, not once.
**Estimated effort**: Low

### Option 3: Emit to a file only, let the consumer tail it
**Description**: Drop the socket; always append JSONL to a path.
**Pros**: Simplest possible implementation.
**Cons**: No backpressure and no liveness signal; the consumer cannot tell a
finished run from a stalled one without polling; concurrent appends from three
processes have the same atomicity caveat for large records.
**Estimated effort**: Low

## Decision

**Option 2**, with a file transport kept as a fallback.

New flags on `can run` / `can up`, all opt-in:

| Flag | Meaning |
|---|---|
| `--events-socket <path>` | Connect to an existing `SOCK_STREAM` Unix socket. `can` is the **client**; the consumer listens. |
| `--events-file <path>` | Append JSONL to a file. Mutually exclusive with `--events-socket`. |
| `--run-id <string>` | Stamped on every event. Defaults to a generated id when an event target is set. |

Envelope, one compact JSON object per line:

```json
{"schema":1,"run_id":"r-1","stream":"proxy","seq":42,"ts_ms":1760000000000,
 "prev_hash":"…64 hex…","event":"egress_request","data":{…},"chain_hash":"…64 hex…"}
```

Field order is fixed and `chain_hash` is **always the last field**, because the
chain is defined over the raw line:

```
body      = the line with the trailing `,"chain_hash":"<64 hex>"` removed (so it ends with `}`)
chain_hash = sha256(body_bytes)
```

`prev_hash` is part of `body`, so each event commits to its predecessor; the
first event of a stream uses 64 zeros. A consumer verifies without re-serializing
anything: strip the suffix, hash the prefix, compare, then check that
`prev_hash` equals the previous line's `chain_hash` and that `seq` increments by
one. This replaces the bespoke field-concatenation chain that `canary_fire` used
(R18) and extends it to every event type.

Event types in schema v1: `run_start`, `policy_resolved` (ADR-0014),
`process_exec`, `egress_request`, `contract_violation`, `dlp_block`,
`canary_fire` (ADR-0012), `exchange` (ADR-0011), `stats` (ADR-0015), `run_end`.
The payload structs live in one file, `crates/can-events/src/schema.rs`, as a
single `Event` enum — the schema is auditable at a glance and
`docs/events-schema-v1.json` is generated from it.

Safety and compatibility notes:

- Event connections and files are opened `CLOEXEC`, so the fd is gone by the time
  the worker `execve`s. The sandboxed workload cannot write to the stream.
- Each process opens its own connection *before* joining any namespace.
- With no event flag, nothing changes: `dlp_block` and `canary_fire` keep going
  to stderr in their existing shape.
- Emission is best-effort and never fails a run: a write error is logged once per
  process and the stream is marked dead. Losing the observer must not change
  what the sandbox enforces.

## Consequences

### Positive
- One documented, versioned contract (`schema: 1`) between `can` and any
  orchestrator, covered by golden-file tests on both sides.
- Tamper-evidence extends from canary fires to the whole run record.
- The event channel is independent of stdout/stderr, so the workload's own
  output stays clean and unparsed.

### Negative
- Consumers must merge streams. Mitigated by documenting the merge rule
  (`ts_ms`, then `stream`, then `seq`) and by keeping per-stream chains intact.
- A third crate (`can-events`) in the workspace. Justified: the CLI, the sandbox
  and the proxy all emit, and none of them should depend on another's internals.

### Neutral
- `can-proxy::events` keeps its `dlp_block`/`canary_fire` entry points and now
  delegates to `can-events` when a stream is installed.

## Follow-up Actions
- [ ] ADR-0011 exchange capture, ADR-0012 tagged canaries, ADR-0013 loopback
      routing, ADR-0014 resolved policy, ADR-0015 stats events.
- [ ] Publish `docs/events-schema-v1.json` and keep it generated from
      `can-events`.
