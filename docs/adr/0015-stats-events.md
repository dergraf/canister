# ADR-0015: Stats Events

## Status
Accepted

## Date
2026-09-22

## Context

A long CI run should show progress while it runs — requests so far, blocks so far, how
slow the proxy is — and should end with totals that a dashboard can chart. The
per-request events (ADR-0010) already contain everything needed to derive those numbers,
but deriving them means the consumer keeps running aggregates for every in-flight run, and
a consumer that joins late or drops a batch has no way to resynchronize.

The obvious industry answer is OpenTelemetry. That would put an OTLP exporter, a metrics
SDK and a batching pipeline inside `can` — a single, dependency-free binary whose job is
to enforce a sandbox. It would also mean configuring an endpoint in every environment
where `can` runs, including CI runners with no egress.

## Options Considered

### Option 1: Export OpenTelemetry metrics from `can`
**Description**: Link the OTel Rust SDK, export OTLP to a configured endpoint.
**Pros**:
- Standard protocol, works with existing backends without a consumer.
**Cons**:
- Significant dependency surface in a security-critical binary.
- Needs network egress from the sandbox host, precisely where egress is restricted.
- Duplicates the event stream: two transports, two failure modes, two things to secure.
**Estimated effort**: Medium–High

### Option 2: Counters in the event stream; the consumer makes metrics (chosen)
**Description**: Emit a `stats` event with cumulative counters and a fixed-bucket latency
histogram on an interval, plus one final snapshot at shutdown. The orchestrator converts
them into whatever metric system it uses.
**Pros**:
- No new dependency and no new transport: `can` stays a single binary.
- The consumer already has the stream, its ordering and its integrity checks.
- Cumulative counters mean a dropped event costs resolution, not correctness.
**Cons**:
- Not directly scrapeable; something must translate. That something already exists.
**Estimated effort**: Low

### Option 3: Derive everything consumer-side from per-request events
**Description**: No `stats` event at all.
**Pros**: Nothing to emit.
**Cons**: A consumer joining mid-run, or one that drops a batch, cannot recover totals;
and a run with capture enabled may throttle per-event processing exactly when progress
display matters most.
**Estimated effort**: None

## Decision

**Option 2.** The proxy process emits `stats` every `--stats-interval-ms` (default 5000;
`0` disables) and once more when it shuts down.

Payload, all **cumulative since the process started**:

| Field | Keyed by |
|---|---|
| `requests_by_decision` | `allowed` / `blocked` |
| `contract_violations_by_reason` | contract reason code (`method-not-allowed`, …) |
| `dlp_blocks_by_detector` | detector id |
| `canary_fires` | `"<data_class>:<allowed\|blocked>"`; generated tripwires use `-` |
| `proxy_latency_ms` | fixed-bucket histogram |

Latency buckets are **fixed**, not configurable, so snapshots from different runs and
different machines are directly comparable: upper bounds
`5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000` milliseconds, plus a final `+Inf`
count. `counts` has one entry per bound plus that `+Inf` entry; `sum_ms` and `count` allow
computing a mean.

Cumulative rather than delta: a consumer subtracts consecutive snapshots to get a rate,
and a lost event only coarsens the picture. `process_exec` is *not* counted here —
consumers count the per-exec events, which carry the path and the decision.

**Final snapshot.** The sandbox used to `SIGKILL` the proxy during teardown, which would
lose up to one interval of counters. It now sends `SIGTERM` first, waits up to 250 ms, and
falls back to `SIGKILL`; the proxy's accept loop selects on the signal, emits the final
snapshot and exits. A wedged proxy therefore still cannot delay teardown beyond the
timeout.

## Consequences

### Positive
- Progress and totals without an OTel dependency, an exporter endpoint or a second
  transport.
- Fixed buckets make latency comparable across runs, which is what a regression check
  needs.
- Consumers that already read the stream get metrics for free.

### Negative
- Bucket bounds are baked in; changing them later changes the shape of historical data.
  Chosen to span the range that matters for a proxied request (a few ms to a few seconds).
- Teardown gained a signal handshake with a bounded 250 ms worst case.

### Neutral
- The counters live in a process-global collector, matching how the event stream and the
  canary counter already work: the proxy is one process per run.

## Follow-up Actions
- [ ] The orchestrator maps `stats` onto its metric definitions (`canister.*` in
      the consumer's own metric definitions).
- [ ] Revisit if a second, long-lived proxy mode ever appears; per-server collectors would
      then be needed.
