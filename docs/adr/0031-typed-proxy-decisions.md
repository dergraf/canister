# ADR-0031: Proxy Decisions Are Typed Values, Recorded From the Value

## Status
Accepted

## Date
2026-10-06

## Context

Every request the proxy handles inside `handle_inner_request` produces exactly one
`egress_request` event. That invariant holds, and it is worth keeping. How the event
learns what was decided is the weak part:

1. A refusal is an `ErrorKind` variant. `ProxyError::into_response` turns it into a
   status, a body and an `x-canister-error` header string.
2. `static_str` maps that string to a `'static` one from a fixed list. A kind missing
   from the list becomes `proxy-error`, silently. ADR-0030's `foreign-credential`
   was missing until a test caught it.
3. `events::egress_request` reads the header back and maps the string to a decision
   and a reason (`Some(other) => other` for anything it does not know).

So one decision passes through three string mappings in two files, and only tests
notice when they disagree. Refusals outside that path (a `CONNECT` the policy gate
refuses, a transparent connection without SNI or one whose client rejects the CA, a
`CONNECT` the sink accepts) call `events::egress_blocked` directly with a reason
string written at the call site: five call sites in two files. The supervisor
(`process_exec`) and the decoy watcher (`fs_access`) emit their own events in their
own crates, which is fine: they are other components.

## Options Considered

### Option 1: One `Refusal` type that knows its status, header and reason (chosen)
**Description**: `ErrorKind` becomes the single description of a refusal. Each
variant states its status, its `x-canister-error` value and its event reason in one
`match`, so adding a variant without all three does not compile. `into_response` puts
the variant itself in the response's extensions, and `egress_request` reads the
decision from there instead of parsing the header. `egress_blocked` takes a variant
too, not a string. The header stays exactly as it is, for clients and for
`docs/refusals.md`.
**Pros**:
- A refusal kind cannot exist without its header and its event reason.
- `static_str` and the header parsing go away; so does `Some(other) => other`.
- Behaviour and output are unchanged, so the existing tests verify the refactor.
**Cons**:
- Touches every refusal path in `can-proxy` at once.
**Estimated effort**: Medium.

### Option 2: Keep the strings, test that the three mappings agree
**Description**: A test that enumerates the kinds and checks each mapping.
**Pros**:
- Small.
**Cons**:
- The test has to be kept in step by hand, which is the same problem one level up.
**Estimated effort**: Low.

## Decision

Option 1, as a behaviour-preserving refactor: the same statuses, headers, bodies and
event reasons, verified by the existing proxy tests without modification. The
upstream outcomes that are not refusals (`upstream-timeout`, `upstream-error`) stay
`Allowed` with a reason, as today.

## Consequences

### Positive
- The next refusal kind is added in one place.
- Events and responses cannot drift apart.

### Negative
- A large mechanical diff in `can-proxy`.

### Neutral
- No change to the event schema or to what clients see.

## Follow-up Actions
- [ ] `ErrorKind` carries status, header and reason; the variant in the response's
      extensions; `egress_request` and `egress_blocked` take it
- [ ] Remove `static_str` and the header parsing
