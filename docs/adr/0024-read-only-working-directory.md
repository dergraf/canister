# ADR-0024: A Read-Only Working Directory

## Status
Accepted

## Date
2026-10-04

## Context

`can run` bind-mounts the host's working directory into the sandbox, **writable**, so
development workflows work as they do outside it: `cargo build`, `mix new`, a script that
writes its output next to itself. It is mounted whatever the recipe's `[filesystem]
write` entries say, and the resolved policy (ADR-0014) does not mention it.

For a CI consumer that runs an untrusted workload in a checkout, that is the one
writable path nobody declared. The workload can change the files the job uses after it
— sources, configuration, the scripts of the next step — and a reviewer reading the
policy sees `write = []` and concludes it could write nowhere. A consumer that limits
where a workload may write has no way to enforce that limit, or even to see it.

## Options Considered

### Option 1: Make the working directory read-only by default
**Description**: Mount it read-only unless a `write` entry names it.
**Pros**:
- The safe default; the policy says everything.
**Cons**:
- Breaks every existing development workflow that writes into the project.
**Estimated effort**: Low, with a large compatibility cost.

### Option 2: A `[filesystem] workdir` setting, writable unless set (chosen)
**Description**: `workdir = "write" | "read"`, default `write`. With `read`, the working
directory is mounted read-only; `write` entries that cover it make it writable, and
`write` entries inside it are mounted again on top of it so they stay writable. The
resolved policy always states the value.
**Pros**:
- No change for existing users; a CI layer opts in with one line.
- The policy shows whether the working directory is writable, either way.
**Cons**:
- The resolved policy gains a key, so every policy hash changes once.
**Estimated effort**: Low.

### Option 3: Do not mount the working directory at all
**Description**: Treat it like any other path: visible only if `read` or `write` names it.
**Pros**:
- One rule for every path.
**Cons**:
- Workloads that only read their own project (most CI workloads) would need a `read`
  entry naming a path that differs per checkout.
**Estimated effort**: Medium.

## Decision

Option 2. When recipes are composed, an explicit `read` in any layer wins over `write`,
as `refuse` wins for `undeclared_hosts` (ADR-0018): the narrower access cannot be
widened by a later layer. A `write` entry is still a grant, so naming the working
directory (or a parent of it) under `write` makes it writable again; that is visible
in the policy.

## Consequences

### Positive
- A CI layer can say "this workload writes nowhere but here", and the policy says so.
- The evidence records whether the working directory was writable.

### Negative
- Every resolved policy's hash changes once, because `filesystem.workdir` is now
  rendered. ADR-0014 accepts that a serialization change does this; consumers that pin
  policy hashes re-record them once.

### Neutral
- The default is unchanged.

## Follow-up Actions
- [x] `[filesystem] workdir`, merge, resolution, mount, unit and integration tests
