# ADR-0032: The Sandbox's Mounts Are Planned as Data, Then Applied

## Status
Accepted

## Date
2026-10-06

## Context

`overlay::setup_filesystem` builds the sandbox's filesystem imperatively, in one
ordered sequence: a tmpfs root, the directory skeleton, read-only binds of allowed
paths, writable binds, a tmpfs `/tmp`, the working directory (writable, or read-only
with writable paths mounted again inside it, ADR-0024), denied paths hidden inside
mounted ones, masked files, decoys (ADR-0019), `/proc`, `/dev`, `pivot_root`. The
decisions (what goes where, what wins, what is skipped) are interleaved with the
`mount(2)` calls that carry them out.

Each recent change added a step whose interactions with the others can only be
checked in a real mount namespace: a deny below an allowed path, decoys that must
not land under a writable mount, a read-only working directory with writable holes.
The next ones are already known: a working directory mounted as only the paths a
policy lists inside it, and overlays of trust bundles. Tests of the ordering rules
today need user namespaces and run in the integration suite only.

## Options Considered

### Option 1: A pure `MountPlan`, then an executor (chosen)
**Description**: A function computes a `MountPlan` from the filesystem config, the
working directory and what exists on the host (a probe passed in, so tests can fake
it): an ordered list of steps, each a target, a source and a kind (tmpfs, bind
read-only, bind writable, bind writable no-exec, mask with `/dev/null`, decoy,
directory). Skipped entries are in the plan too, with the reason. A second function
applies a plan with `mount(2)` and changes nothing about it. `can check` can print
the plan.
**Pros**:
- The ordering rules (parents before children, a real grant before a decoy, a deny
  inside a mount hidden after it) become unit tests on data, without namespaces.
- A reviewer reads one function that decides, and one that only executes.
- The next filesystem feature is a rule in the planner, not another step in a
  sequence.
- The plan shows a user why a path is or is not visible.
**Cons**:
- A large refactor of a security-critical file. It has to preserve behaviour
  exactly, checked by the existing integration tests.
**Estimated effort**: Medium to high.

### Option 2: Keep the sequence, add integration tests per interaction
**Description**: Leave the code, test more combinations in namespaces.
**Pros**:
- No refactor risk.
**Cons**:
- The tests grow with the square of the features, and run only where user
  namespaces do.
**Estimated effort**: Medium, recurring.

## Decision

Option 1, in two steps. First the refactor: the planner and executor reproduce
today's mounts exactly, the existing integration tests pass unchanged, and the
planner gets unit tests for every ordering rule `setup_filesystem` encodes today.
Then features build on it: a working directory mounted as only the paths listed
inside it is a planner rule.

`/proc`, `/dev` and `pivot_root` stay as they are; they do not depend on
configuration.

## Consequences

### Positive
- Filesystem rules are tested as data, on any machine.
- `can check` can explain what the sandbox will see.

### Negative
- A refactor of mount code with no new feature of its own.

### Neutral
- No change to what a sandbox sees.

## Follow-up Actions
- [ ] `MountPlan`, the planner with a host probe, the executor
- [ ] Unit tests for each ordering rule; the integration tests unchanged
- [ ] `can check` prints the plan
- [ ] `workdir = "listed"`: only the paths listed inside the working directory
