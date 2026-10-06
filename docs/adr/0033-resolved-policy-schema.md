# ADR-0033: The Resolved Policy Has a Published Schema and a JSON Preview

## Status
Accepted

## Date
2026-10-06

## Context

Tools generate recipes for `can`: an orchestrator compiles its own policy into a
recipe and passes it with `--recipe`, next to `can`'s library recipes. What runs is
the merge of all of them. The merge has a rule per field (about 34 merge functions):
any layer turning `transparent` on wins, an explicit `refuse` wins over `sink` for
undeclared hosts, lists are unions, credential scope survives only from trusted
recipes. The result is visible after the fact, in the `policy_resolved` event
(`policy`, `policy_sha256`), and before it with `can recipe show`, as TOML.

A tool that compiled a policy cannot easily check that what will run is what it
meant: the preview is TOML, its digest is not the one the event will carry, and the
shape of the resolved policy is documented only by the Rust types. The event schema
is published (`docs/events-schema-v1.json`); the policy inside `policy_resolved` is
an untyped `serde_json::Value` in it.

## Options Considered

### Option 1: Publish the resolved policy's schema, preview it as JSON with its digest (chosen)
**Description**: `docs/policy-schema-v1.json` is generated from the config types,
like the event schema, and checked by the same kind of golden test.
`can run --print-policy` (and `can up`) prints the resolved policy as the
`policy_resolved` event will carry it, with the same `policy_sha256`, and exits
without starting a sandbox. It sits in the run's own path, after what `can run` adds
itself (the canaries file, `--port`, the masked `canister.toml`), which a
`can recipe show` preview would miss. A tool resolves its recipes before the run,
compares the result with what it compiled, and later finds the same digest in the
evidence.
**Pros**:
- Recipes, their trust rules and the merge stay as they are.
- A tool can verify its compilation against `can`'s own resolution, by digest.
- The resolved policy gets a documented, versioned shape.
**Cons**:
- The tool still has to compare: `can` does not refuse a resolution that differs
  from what the tool expected.
**Estimated effort**: Low.

### Option 2: Accept a resolved policy as input instead of recipes
**Description**: `can run --policy resolved.json`, skipping the merge.
**Pros**:
- No merge surprises at all.
**Cons**:
- Credential scope comes only from trusted recipes. A resolved policy from a file
  would either carry none, so a provider's key swap could not be used, or need a new
  trust mechanism for whole policies. Both are larger than the problem.
**Estimated effort**: High.

## Decision

Option 1. The digest of the preview and of the event are computed by the same
function over the same canonical serialization, through one type that is also the
published schema. The schema is versioned with the
file name; a change to it is a golden-test diff in review.

## Consequences

### Positive
- A policy compiler can check, before running, that `can` will enforce what it
  compiled, and the evidence names the same digest.

### Negative
- One more generated file to keep current (enforced by its test).

### Neutral
- Nothing changes for people who write recipes by hand.

## Follow-up Actions
- [x] `docs/policy-schema-v1.json` and its golden test
- [x] `can run --print-policy` and `can up --print-policy`, with `policy_sha256`
