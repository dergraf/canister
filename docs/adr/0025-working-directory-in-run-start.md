# ADR-0025: The Working Directory in `run_start`

## Status
Accepted

## Date
2026-10-04

## Context

The resolved policy (ADR-0014) names paths absolutely. Some of them lie under the
directory the workload runs in: a project's own `canister.toml` is masked by absolute
path, and a recipe's `write` entries often name directories of the project. The same
project checked out at `/home/dev/project` and at `/runner/work/project` therefore
yields two resolved policies with two hashes, and a consumer that compares policies
across runs (to notice a changed sandbox) sees a change where there is none.

`run_start` does not say where the run happened, so a consumer can only guess the
project root, for instance from the masked manifest's directory, which depends on a
detail of `can up`.

## Options Considered

### Option 1: Record the working directory in `run_start` (chosen)
**Description**: An optional `working_dir` field with the absolute path.
**Pros**:
- Additive: older consumers ignore it, older streams parse without it.
- A consumer relativizes whatever it needs against a stated root.
**Cons**:
- Consumers that want location-independent policies do the relativizing themselves.
**Estimated effort**: Low.

### Option 2: Emit paths under the working directory relative in `policy_resolved`
**Description**: Rewrite such paths as `./…` before hashing.
**Pros**:
- Location-independent hashes for everyone.
**Cons**:
- Changes every existing hash and the meaning of the policy document, which then no
  longer says where the sandbox actually mounted things.
**Estimated effort**: Medium.

## Decision

Option 1. The policy keeps stating what was enforced, exactly; the event that opens the
stream states where.

## Consequences

### Positive
- Runs of the same project in different checkouts can be compared reliably.

### Negative
- The absolute path of the checkout appears in the evidence. It already did, through
  the masked manifest and any project paths in the policy.

### Neutral
- Schema v1 is unchanged in shape: one optional field.

## Follow-up Actions
- [x] `RunStart.working_dir`, golden fixture, schema, integration test
