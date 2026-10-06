# ADR-0032: The Configured Mounts Are Planned as Data, Then Applied

## Status
Accepted

## Date
2026-10-06

## Context

`overlay::setup_filesystem` builds the sandbox's filesystem in one ordered sequence:
a tmpfs root, the directory skeleton, read-only binds of `read` entries, writable binds
of `write` entries, a tmpfs `/tmp`, the working directory (writable, or read-only with
the `write` entries inside it mounted again on top, ADR-0024), denied paths hidden
inside mounted ones, masked files, decoys (ADR-0019), `/proc`, `/dev`, `pivot_root`.

Several of its decisions are already pure, tested helpers: whether the working
directory is writable, which `write` entries lie inside it, which denied paths lie
inside a mount, where a decoy may go. What they lack is one place that states the
order and the outcome of every configured entry. The order is what the next feature
depends on: mounting the working directory as only the paths listed inside it means
every entry inside it has to be mounted *after* the working directory, or the
directory hides it.

Some checks can only run against the sandbox being built: whether a masked path, a
decoy target or a denied path exists inside the new root, and whether a denied path
is a symlink there. Planning those as data would mean modelling the sandbox's view of
the host in the planner, which is more risk in this code than it is worth.

## Options Considered

### Option 1: Plan the configured mounts; keep the checks on the new root in the executor (chosen)
**Description**: A pure function computes a `MountPlan` from the filesystem config,
the working directory, whether the writable mounts are `noexec`, and a host probe
(does a host path exist, is it a directory), which tests replace with a fake. The plan
is an ordered list of steps: bind read-only, bind writable, the `/tmp` tmpfs, the
working directory, hide a denied path, mask, place a decoy. A `read` or `write` entry
that will not be mounted is a skipped step with its reason (missing, denied). A
second function applies the plan; it alone calls `mount(2)` and it alone checks the
new root (existence, symlinks), as today. The fixed parts (root, skeleton, `/proc`,
`/dev`, `pivot_root`) stay outside the plan.
**Pros**:
- The order and outcome of every configured entry are one value, tested without
  namespaces.
- A filesystem feature that depends on order is a rule in the planner.
- No model of the sandbox's view is needed; those checks stay where they are.
**Cons**:
- A refactor of mount code. It must issue the same mounts in the same order, which
  the existing integration tests check.
**Estimated effort**: Medium.

### Option 2: Plan everything, including the checks on the new root
**Description**: Model which host paths each sandbox path comes from, and decide
masks, decoys and hidden paths in the planner too.
**Pros**:
- The whole filesystem as data.
**Cons**:
- The model of the sandbox's view is new code with the same failure modes as the
  mounts it describes.
**Estimated effort**: High.

## Decision

Option 1, in two steps.

1. **Refactor.** The planner and the executor issue today's mounts in today's order;
   the existing unit and integration tests pass unchanged, and the planner gets tests
   for each rule it encodes.
2. **`[filesystem] workdir = "listed"`.** The working directory becomes an empty
   tmpfs. The `read` and `write` entries inside it are mounted into it, after it, and
   it is then made read-only, so nothing else from the checkout is visible: no `.git`,
   no untracked files. A file the workload creates in the working directory outside a
   `write` entry fails as it would in a read-only checkout. When recipes compose, an
   explicit `listed` wins over `read` and `write`, since it is the narrowest. The
   resolved policy states it as any other value of `workdir`.

## Consequences

### Positive
- The order of configured mounts is tested as data.
- A tool that compiles a closed-world policy can hand `can` exactly the paths a
  workload may see inside its checkout.

### Negative
- `listed` needs every path the workload reads inside its checkout to be listed;
  a missing one is absent, not an error.

### Neutral
- `/proc`, `/dev` and `pivot_root` are unchanged.

## Follow-up Actions
- [ ] `MountPlan`, the planner with a host probe, the executor
- [ ] `workdir = "listed"`
- [ ] `can check` prints the plan
