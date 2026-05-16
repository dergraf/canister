# ADR-0006: Unified Egress Model

## Status
Accepted

## Date
2026-05-14

## Context

The original network policy mixed two orthogonal concepts in a single
boolean. `NetworkConfig::deny_all` toggled "no outbound at all", and the
presence of `allow_domains` / `allow_ips` implicitly enabled the L7 proxy.
Direct outbound (skip the proxy) was a third unnamed state inferred from
the absence of both. The result:

- Three policy modes encoded across two unrelated fields.
- Adding the L7 proxy filtering layer made the "is the proxy on?"
  question depend on a serde-level negation.
- Recipes that wanted to compose ("base + project") had ambiguous merge
  semantics — does `deny_all = false` in an overlay override the base's
  `deny_all = true`, or only narrow it? The TOML didn't say, and `merge()`
  had to guess.
- Documentation papered over the ambiguity by enumerating "modes" in prose
  that the type system didn't enforce.

Before shipping the L7 proxy as a first-class feature, the egress model
needed an explicit, exhaustive enum so the serde round-trip, the merge
rules, the seccomp `connect()` enforcement, and the docs all referenced
the same three states.

## Options Considered

### Option 1: Keep `deny_all: bool` + proxy auto-detect

**Description**: Preserve the existing boolean, document the three modes
in prose, and disambiguate merge by last-writer-wins.

**Pros**:
- Zero migration risk for existing recipes.
- Smallest diff to the policy layer.

**Cons**:
- Permanently locks in the implicit third state ("direct").
- The CLI surface (`can` recipe layering) still can't express "I want
  this recipe to explicitly opt me out of the proxy" — it can only
  remove `deny_all` and hope nothing else flips it back.
- New proxy-related fields (interceptors, body caps, timeouts) all
  need their own "is the proxy on?" predicate, repeated everywhere.

**Estimated effort**: Low

### Option 2: New `egress` enum, `none | proxy-only | direct`

**Description**: Add `egress: Option<EgressMode>` to `NetworkConfig`,
default to `proxy-only`, deprecate `deny_all`. Merge rules become
last-Some-wins, identical to other Option fields. The seccomp
`enforce_proxy_egress` and the proxy server share a single decision
point: the resolved `EgressMode`.

**Pros**:
- One field, three exhaustive states, no implicit fourth.
- `match` exhaustiveness makes new modes (e.g., `mtls-only`) trivial.
- Docs, schema (`schemars`), and the seccomp filter agree by
  construction.
- Recipes can be explicit about which layer of policy they're setting.

**Cons**:
- Touches every recipe file that referenced `deny_all`.
- Requires a coordinated migration: the embedded `default.toml` and all
  `recipes/*.toml` must update together with the source.

**Estimated effort**: Medium

### Option 3: Separate `proxy: bool` + `direct: bool`

**Description**: Two booleans, with a validation rule forbidding
`proxy && direct`.

**Pros**:
- Maximally granular.

**Cons**:
- Same disambiguation problem as Option 1 (which boolean wins on merge?).
- Two booleans can encode four states; the fourth is nonsensical and
  needs runtime validation rather than a compile-time enum.

**Estimated effort**: Medium

## Decision

**Option 2.** The unification landed in commit `6f81746` ("feat: unify
egress model and harden proxy enforcement").

`NetworkConfig::egress: Option<EgressMode>` with variants `None`,
`ProxyOnly`, `Direct`. The effective mode is resolved by
`NetworkConfig::egress()` (defaulting to `ProxyOnly`). Recipe merge follows
the rest of the policy layer's last-Some-wins rule.

The seccomp `connect()` filter consults `policy.enforce_proxy_egress`,
which is set when `EgressMode::ProxyOnly` resolves. The proxy server
likewise reads the same enum to decide whether to apply outbound policy
checks. There is no longer an implicit third state.

`deny_all` was removed (no deprecation period — pre-release). Recipes that
previously set `deny_all = true` now set `egress = "none"`.

## Consequences

### Positive
- Recipe merge is unambiguous and matches every other policy field.
- The L7 proxy enforcement has a single load-bearing predicate
  (`enforce_proxy_egress`) instead of a constellation of derived booleans.
- Documentation can refer to the same three modes the serde schema
  describes — the README's "Network Modes" matrix maps 1:1 to the enum.

### Negative
- All recipes shipped before commit 6f81746 had to be rewritten. (Done
  in the same commit.)
- Users who copy/paste old recipes from chat history or external blogs
  will see `unknown field deny_all` and need to migrate manually. The
  strict `deny_unknown_fields` parsing is intentional — silent ignore
  would hide migration failures.

### Neutral
- The proxy/seccomp parity test (`tests/integration/t_dns_filtering.sh`
  test 4) exists precisely because the two enforcement layers must agree
  on the resolved mode. The integration tests now lock that contract.

## Follow-up Actions
- [x] Remove `deny_all` from all recipes (commit 6f81746).
- [x] Update `RecipeFile::merge` to round-trip `egress` (commit 6f81746).
- [x] Update README + `docs/CONFIGURATION.md` to describe the three modes.
- [ ] Add an `egress = "mtls-only"` mode once mTLS work lands (tracked
      separately).
