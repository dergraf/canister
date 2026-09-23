# ADR-0016: Signed Event-Stream Seals

## Status
Accepted

## Date
2026-09-23

## Context

The event stream (ADR-0010) is hash-chained: each line commits to its predecessor,
so no line can be changed, dropped or reordered without breaking the chain. That
makes a stream **internally consistent**.

It does not make it **authentic**. The chain is computed from the bytes with a
published algorithm, so anyone holding the file can rewrite a line and recompute
every hash after it. The result verifies perfectly. Everything downstream of `can`
sits in that gap: the orchestrator that reads the socket, the CI job that stores
the file, an artifact store, and the vendor of any tool that reports on it.

That gap matters because of what the stream is used for. Consumers build evidence
out of these events — "the workload sent this value to this host, in 2 of 13
runs" — and the reader of such a statement is entitled to ask who vouches for the
bytes. Today the answer is "whoever handed you the file", which is the weakest
possible answer and the one an auditor will reject first.

A second, more mundane failure has the same shape: a tool that reads a stream
cannot currently distinguish "this file was produced by `can`" from "this file was
produced by something that writes the same format".

## Options Considered

### Option 1: Leave the chain as the only integrity claim
**Description**: Document that the chain proves consistency, not authenticity, and
leave authenticity to the transport and the storage.
**Pros**:
- No new dependency, no key management, nothing to get wrong.
- For a local run inspected by the person who started it, the distinction is moot.
**Cons**:
- The evidence cannot travel: the moment it leaves the machine that produced it,
  nothing in the file supports its own provenance.
- A consumer must trust every hop, which is exactly the property compliance
  evidence is supposed to remove.
**Estimated effort**: None

### Option 2: Sign every event line
**Description**: Each line carries its own signature.
**Pros**:
- A truncated stream is still verifiable line by line.
**Cons**:
- An Ed25519 signature per event costs ~64 bytes and a scalar multiplication on a
  hot path that already runs inside the proxy for every request.
- Redundant: the chain already binds the lines together, so signing each one
  re-proves what the chain proves.
**Estimated effort**: Medium

### Option 3: Sign the chain head once, as a closing seal (chosen)
**Description**: When a process has nothing left to emit, it writes a final
`stream_seal` event: an Ed25519 signature over the run id, stream name, event count
and final chain hash. One signature per stream, at the end.
**Pros**:
- One signature commits to the entire stream, because the chain commits each event
  to its predecessor. Cost is one signing operation per process per run.
- The signed message is four fields and a domain separator — reproducible without
  a JSON parser, which keeps an independent verifier small enough to be written by
  a sceptic in an afternoon.
- Including run id, stream name and count in the message stops a valid seal being
  pasted onto a different stream, or surviving events being dropped from the one it
  closes.
- Entirely opt-in: with no key, behavior is byte-for-byte what it was.
**Cons**:
- A stream that ends abruptly (a killed proxy) carries no seal at all. Mitigated by
  treating unsealed as *unsealed* rather than as tampered: crashing is not forgery,
  and a verifier that conflates them teaches people to ignore it.
- Key management becomes the operator's problem. That is the intended trade: it
  narrows "trust the whole pipeline" to "trust one key", which is the smallest
  thing a deployment can actually defend.
**Estimated effort**: Low

## Decision

**Option 3.** Concretely:

- New event type `stream_seal` in schema v1, carrying `algorithm`, `public_key`,
  `signature`, `events` and `chain_head`. It is an ordinary event: it has its own
  `seq`, `prev_hash` and `chain_hash`, so the chain covers the seal too.
- The signed message is exactly:

      canister-event-stream-v1\n<run_id>\n<stream>\n<events>\n<chain_head>

  with `chain_head` in lowercase hex and `events` the number of events preceding
  the seal.
- `--events-sign-key <path>` names an Ed25519 key, given as 32 raw bytes or 64 hex
  characters. It is read in the CLI process before any namespace is entered and
  never enters the sandboxed workload's environment.
- `EventStream::seal()` emits the seal and closes the stream, so nothing can be
  appended after the signature. Calling it twice is a no-op, because shutdown paths
  are never as linear as they look.
- The CLI seals after `run_end`; the proxy seals when it receives SIGTERM, before
  the sandbox's SIGKILL follows.
- Without a key, `seal()` closes the stream and writes nothing. An unsigned seal
  would look like evidence of authenticity while proving nothing.
- New dependency: `ed25519-dalek` (default features off, `std` on). Justified by
  being the standard pure-Rust implementation of the one primitive needed; the
  alternative, reusing the proxy's `ring` through `rustls`, would pull a TLS stack
  into a crate that has no business with one.

## Consequences

### Positive
- Evidence can travel. A consumer that knows the public key can distinguish the
  bytes `can` wrote from bytes produced afterwards, without trusting the transport,
  the CI job, or the tool reporting on them.
- A forger who rewrites a line *and* rebuilds the entire chain is caught, which is
  the only attack the chain alone cannot see.
- The seal states who signed; which keys are trusted stays a consumer decision.

### Negative
- Operators who want authenticity must provision and protect a key. Documented as
  a run-level secret; a stolen key defeats the seal, which is the ordinary property
  of signatures and is stated plainly rather than papered over.
- A new event type in schema v1. Consumers that reject unknown event types need
  updating — the schema is published and versioned for exactly this.

### Neutral
- The seal proves nothing about the machine or the key's custody. Machine
  attestation is a separate question and a later ADR if it is ever asked for.

## Follow-up Actions
- [ ] Supervisor stream: seal it too once it has a defined shutdown point.
- [ ] Document key provisioning for CI, where the key is a run-level secret.
