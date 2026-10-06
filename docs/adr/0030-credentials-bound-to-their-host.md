# ADR-0030: A Credential-Scoped Host Takes Only the Swapped Credential

## Status
Accepted

## Date
2026-10-06

## Context

`[network.dlp] fake_secrets` gives the sandbox a fake credential under the real
variable's name. The proxy replaces the fake with the real value, but only on a host
the credential is scoped to (`[[host]] allow_credentials`). The swap is a
substitution: wherever the fake appears in a header bound for an authorized host, the
real value takes its place. Everything else is forwarded unchanged.

That leaves two gaps on exactly the hosts that matter most:

- **A credential the workload brings itself reaches the host unchanged.** A request
  to `api.anthropic.com` carrying a key the workload obtained elsewhere goes out with
  that key. Data the workload sends is then stored under another account, by a
  provider API that keeps it (batches, assistants, uploaded files). The host is
  allowed, the data may reach it, and nothing in the request is the fake.
- **Nothing records which credential a request carried.** Captured headers redact
  `authorization` and `x-api-key`, rightly, so a consumer of the event stream cannot
  tell the swapped credential from a foreign one.

## Options Considered

### Option 1: Classify the credential, record it, and optionally refuse a foreign one (chosen)
**Description**: On a host with at least one authorized swap, the proxy classifies
each request's credential before the swap, from a fixed list of credential headers
(`authorization`, `x-api-key`, `api-key`, `x-goog-api-key`):

- `swapped`: a credential header carries an authorized fake;
- `foreign`: a credential header carries something else;
- `none`: no credential header.

`egress_request` gains an optional `credential` field with that value, on such hosts
only. With `[network.dlp] bind_credentials = true`, a `foreign` request is refused
(`x-canister-error: foreign-credential`, `egress_request` blocked with reason
`foreign_credential`). It is refused after its body has been scanned and captured, as
the sink does, so what it carried is still evidence.
**Pros**:
- Closes the path without knowing any provider's header format: the fake is the
  marker.
- The classification is useful without the refusal: a monitor-mode run shows foreign
  credentials before anyone turns on enforcement.
- `none` stays allowed, so unauthenticated endpoints on a scoped host keep working.
**Cons**:
- A credential sent in a header outside the list, the query string or the body is
  `none`, not `foreign`. The list is one constant and grows with the providers.
**Estimated effort**: Low.

### Option 2: Replace the credential header unconditionally
**Description**: On a scoped host, drop whatever credential arrives and set the real
one.
**Pros**:
- No foreign credential can pass, whatever the header.
**Cons**:
- The proxy would have to know each provider's header name and format
  (`Authorization: Bearer`, `x-api-key`, query keys), per credential. That knowledge
  belongs in recipes, which do not carry it today.
**Estimated effort**: Medium.

## Decision

Option 1. `bind_credentials` is off by default, and any recipe layer turning it on
wins when recipes compose: it narrows what may leave. The credential headers are one
constant in `secret_swap.rs`. The classification runs on the request as the workload
sent it, before the swap, and the refusal sits where the swap would have run.

Provider recipes gaining method and path contracts for their inference endpoints is
a separate change to the recipes, not to the proxy.

## Consequences

### Positive
- A workload cannot use a scoped host with its own credential once the flag is on.
- Consumers can see which credential every request to a scoped host carried.

### Negative
- One more refusal reason to document (`docs/refusals.md`).

### Neutral
- Without the flag, behaviour is unchanged apart from the new optional field.

## Follow-up Actions
- [x] Classification, the `credential` field, `bind_credentials`
- [ ] Method and path contracts in the provider recipes
