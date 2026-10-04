# ADR-0026: `canister.lock` and Recipe Sources

## Status
Accepted. Builds Phases 2 and 3 of ADR-0005, and changes one decision of it
(a mismatch refuses, it does not warn).

## Date
2026-10-04

## Context

ADR-0005 designed a lockfile (Phase 2) and remote recipe sources (Phase 3); neither was
built. Two gaps follow from that:

- **No reproducible sandbox.** `can init` and `can update` install the recipe library
  from a branch, and nothing records which recipe content a project's sandbox was
  composed from. Two machines with different library versions build different sandboxes
  from the same `canister.toml`, silently.
- **No credential scope outside the official recipes.** The trust gate (ADR-0008) keeps
  `allow_credentials` and `fake_secrets` only in recipes whose content matches the
  checksums embedded in the binary, or inline in `canister.toml`. An organisation's
  recipe for its own internal service can never carry its credential swap, so every
  project restates it, and a reviewer reviews it in every project.

## Options Considered

### Option 1: The lock as ADR-0005 designed it, warning on mismatch
**Description**: `can lock` pins recipe digests; `can up` warns on a mismatch and fails
only with `--strict-lock`.
**Pros**:
- Gentle for local development.
**Cons**:
- A warning in CI is not read. A lock that may not hold cannot carry trust, so the second
  gap stays open.
**Estimated effort**: Medium.

### Option 2: A lock that holds, and that the trust gate relies on (chosen)
**Description**: With a `canister.lock`, `can up` refuses a recipe that changed or that the
lock does not name, and treats a recipe the lock pins as reviewed, so it keeps its
credential scope.
**Pros**:
- Reproducible by construction: the sandbox is built from the pinned content or not at all.
- The trust anchor is the project's own reviewed files, the same anchor the manifest
  already is.
**Cons**:
- Updating the recipe library breaks `can up` until `can lock --update` records the
  change. That is the point, but it is a step.
**Estimated effort**: Medium.

### Option 3: Signed recipe repositories
**Description**: Sources publish signatures; `can` trusts recipes signed by keys a project
lists.
**Pros**:
- Trust follows the publisher, not each project's review.
**Cons**:
- Key distribution and rotation for every recipe publisher; far more than the gap needs.
**Estimated effort**: High.

## Decision

Option 2.

- **`[sources]`** in `canister.toml`: `name = { git = URL, tag = T }`, `{ git = URL,
  rev = SHA }` or `{ path = DIR }`. A sandbox names `<source>/<recipe>`, by stem
  (recursively) or by path within the source. A source name has no `/`.
- **`canister.lock`** (TOML, version 1): per git source its URL, tag and the revision the
  tag pointed to; per recipe name the SHA-256 of its content. Rendered sorted, so the same
  inputs give the same bytes.
- **`can lock [--update]`** resolves every sandbox's recipes and writes the lock. Existing
  pins are kept unless `--update` is given or `canister.toml` names another repository or
  tag.
- **`can up` with a lock** checks out each git source at its pinned revision (cached by
  repository and revision; a tag that moved is refused when the pin has to be fetched),
  refuses a recipe that changed or is unlocked, and loads pinned recipes with their
  credential scope. Recipes passed with `--recipe` stay untrusted (ADR-0017).
- **Without a lock**, a git source is refused; library and path recipes behave as before.
- The lock is masked inside the sandbox, like `canister.toml`.

## Consequences

### Positive
- A project's sandbox is the same on every machine, or `can up` says why not.
- An organisation can publish recipes for its own services, credential swap included, in
  one repository that projects pin.

### Negative
- Trust now rests on review of `canister.lock` as well as `canister.toml`. A change that
  adds a recipe with credential scope is a change to both, and has to be reviewed as such.
- `can up` fetches git sources on a machine where they are not cached, so it needs `git`
  and network access the first time.

### Neutral
- `can run` is unchanged; sources and the lock apply to `can up`.

## Follow-up Actions
- [x] `[sources]`, `canister.lock`, `can lock`, lock checks and trust in `can up`
- [ ] `can recipe show` for a manifest sandbox, resolving sources the same way
