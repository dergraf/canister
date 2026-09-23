# ADR-0014: Resolved Policy in the Event Stream

## Status
Accepted

## Date
2026-09-22

## Context

A run's evidence — which host was dialled, which canary fired, what was refused — only
means something in the context of the policy that governed it. "No canary reached an
unauthorized host" is reassuring under a strict policy and meaningless under one that
allowed everything.

Policy comes from several layers: `base.toml`, auto-detected recipes, explicit `-r`
flags, the `canister.toml` manifest, CLI overrides, and (now) `--canaries-file`. The
effective document is only known after all of them have merged. `can recipe show` prints
it for humans; nothing published it for a machine.

A consumer also wants a cheap way to compare runs: *did the rules change between this run
and the last one?* Diffing two policy documents answers it, but a stable hash answers it
in one comparison, and a hash is what a report can cite.

## Options Considered

### Option 1: Let the orchestrator run `can recipe show` and hash the TOML
**Description**: No change to `can`; the caller reproduces the resolution itself.
**Pros**: Nothing new to maintain.
**Cons**:
- `recipe show` does not see CLI-level overrides applied during `run`/`up`
  (`--port`, `--canaries-file`, `--strict`), so the two can disagree — exactly when it
  matters most.
- TOML has no canonical form; key order and formatting make hashes unstable across
  versions of the serializer.
**Estimated effort**: None (but wrong)

### Option 2: Emit the resolved policy as JSON with a canonical hash (chosen)
**Description**: With an event stream active, emit `policy_resolved` immediately after
`run_start`, carrying the fully resolved policy and `policy_sha256` over a canonical
serialization of exactly that document.
**Pros**:
- The policy in the record is the policy that ran, including every CLI-level override.
- JSON has a straightforward canonical form (sorted keys, no insignificant whitespace),
  and every consumer language can reproduce it.
- The hash is computable from the `policy` field alone, so it is verifiable rather than
  merely asserted.
**Cons**:
- The event is large-ish (a few KiB). It is emitted once per run.
**Estimated effort**: Low

### Option 3: Hash only, no document
**Description**: Emit `policy_sha256` without the policy.
**Pros**: Tiny event.
**Cons**: A consumer can detect that the policy changed but not what changed, and cannot
verify the hash. The interesting question in an audit is *what* the rules were.
**Estimated effort**: Low

## Decision

**Option 2.** `policy_resolved` is emitted by the CLI process, right after `run_start`,
whenever an event target is configured.

**Resolution.** The emitted document is what `can recipe show` prints, produced by the
same code path (`policy_event::resolved`): the merged policy with `Option` fields replaced
by their effective values, so no reader depends on a default that might change between
versions. `can recipe show` now uses this function too, which keeps the two honest.

**Canonicalization.** The policy is serialized to a `serde_json::Value`, whose object keys
are ordered lexicographically, then written compactly (`,` and `:` separators, no
whitespace). `policy_sha256` is the SHA-256 of those UTF-8 bytes, hex-encoded. In Python
that is:

```python
canonical = json.dumps(event["data"]["policy"], sort_keys=True, separators=(",", ":"))
assert hashlib.sha256(canonical.encode()).hexdigest() == event["data"]["policy_sha256"]
```

Two runs of identical recipes produce identical hashes; any policy change — including one
that only adds an external canary — changes it. This is asserted by an integration test
that runs `can` twice and compares.

**Secrets.** The resolved policy names env vars for `fake_secrets`; it never carries their
values, because the policy document itself does not hold them.

## Consequences

### Positive
- Evidence is self-describing: a report can state the rules under which it was produced
  and prove the statement.
- Drift in the policy between runs is a one-comparison check.
- `recipe show` and the event share a resolver, so what an operator inspects is what the
  run recorded.

### Negative
- The canonical form is a contract: changing serialization changes every hash. It is
  documented here and covered by tests in both `can` and the consumer.
- Recipes that embed environment-dependent paths produce environment-dependent hashes.
  That is correct — the policy really is different — but it means hashes compare within
  an environment, not across developer machines.

### Neutral
- The event is emitted from the CLI process (stream `cli`), before the sandbox forks.

## Follow-up Actions
- [ ] The consumer folds `policy_sha256` into its per-run fingerprint.
- [ ] Consider a `--dry-run --events-file` combination for emitting policy alone.
