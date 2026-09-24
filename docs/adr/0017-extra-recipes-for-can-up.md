# ADR-0017: `can up --recipe`

## Status
Accepted

## Date
2026-09-24

## Context

Two things about a run can only be decided in different places, and until now
those places were mutually exclusive.

**Credential scope must come from a trusted file.** `[[host]] allow_credentials`
and `[network.dlp] fake_secrets` route a real credential to an authorized host, so
ADR-0008's trust rule drops both from any recipe whose contents do not match a
pinned checksum. A recipe a program generates can never match one. The documented
answer is to put credential scope in the project's `canister.toml`, which the
project owns and a reviewer reads — and `can up` is what consumes that manifest.

**Some policy can only be written at run time.** An orchestrator that replaces a
workload's dependencies with local mocks (ADR-0013) cannot know the ports until
the mocks have bound them, so it generates a recipe per run. `can run --recipe`
takes generated recipes; `can up` took none.

So a caller that needed both — a real credential for one host, generated routing
for another — had no way to get them. `can run` can carry the routing but not the
credential scope; `can up` can carry the scope but not the routing. The gap showed
up as a feature that looked configured and silently did nothing: the warning about
dropped credential entries scrolls past in CI, and the run proceeds with a fake
key against a real host.

## Options Considered

### Option 1: Let an explicit flag mark a recipe as trusted
**Description**: `--trust-recipe <path>`: the operator asserts they authored it.
**Pros**:
- Solves it in one flag, for both subcommands.
**Cons**:
- Turns the trust rule into a prompt. The protection exists because recipes are
  fetched from a registry, and an escape hatch that says "trust me" is the thing
  a compromised recipe chain would reach for first.
- Nothing distinguishes an operator's assertion from a script's.
**Estimated effort**: Low

### Option 2: Teach the orchestrator to write a manifest instead
**Description**: Generate a whole `canister.toml` per run, since manifests are
trusted.
**Pros**:
- No change to `can`.
**Cons**:
- Makes *generated* files trusted by construction — a much larger hole than the
  one being closed, and exactly backwards: the manifest is trusted because a human
  wrote it and a reviewer reads it.
- The orchestrator would have to reproduce the project's own policy to extend it.
**Estimated effort**: Medium, and unacceptable

### Option 3: `can up` accepts extra recipes, which stay untrusted (chosen)
**Description**: `can up [name] --recipe <path>` — repeatable, merged after the
manifest's own recipes and overrides. Those recipes go through the same
`RecipeFile::from_file` path as any other, so credential scope in them is dropped.
**Pros**:
- The two concerns land where each belongs: the manifest grants credential scope,
  the generated recipe adds routing, and neither can do the other's job.
- No new trust surface. The flag adds *composition*, not *authority*.
- Merged last, so a generated route wins over the project's own declaration of the
  same host — which is what a mock is for.
**Cons**:
- One more way to compose policy, and composition order is now four layers deep
  (base → manifest recipes → manifest overrides → extra recipes). Documented in
  one place, and the order is the obvious one: most specific last.
**Estimated effort**: Low

## Decision

**Option 3.** `can up` gains a repeatable `--recipe`, merged last.

The trust rule is untouched: an extra recipe is loaded exactly like any other
unpinned recipe, so `allow_credentials` and `fake_secrets` in one are dropped with
the usual warning. Tests pin all three halves of this — an extra recipe's route
wins over the manifest's host block, an extra recipe cannot grant credential
scope, and the manifest still can.

`can up` prints the extra recipes alongside the sandbox's own, so what composed a
run is visible in its output rather than only in the caller's arguments.

## Consequences

### Positive
- A caller can run a workload against a real credentialed host and local mocks in
  the same run, without either weakening the trust rule or generating a manifest.
- The failure that prompted this — credential scope silently dropped from a
  generated recipe — now has a correct configuration to move to.

### Negative
- Composition order matters more than before, and a reader has to know that later
  layers win. It is printed at startup and documented in ARCHITECTURE.md.

### Neutral
- `can run --recipe` is unchanged; this only gives `can up` the same composition
  ability, with the manifest still in charge of what is trusted.

## Follow-up Actions
- [ ] Integration coverage in `tests/integration/` once a scenario needs both
      halves in one run.
