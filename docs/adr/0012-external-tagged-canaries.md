# ADR-0012: External, Tagged Canaries

## Status
Accepted

## Date
2026-09-22

## Context

`can` already generates canary tokens (`CanarySet::generate`), injects them into the
sandbox environment under `CANISTER_CANARY_*` names, and treats any appearance on egress
as exfiltration with zero false positives — the value exists nowhere else, so it cannot
legitimately leave.

An orchestrator evaluating an agent has a different problem. It generates *synthetic
data* the workload is meant to use — a policyholder's AHV number, an IBAN, a diagnosis
code — and needs to know **where each class of data actually flowed**. Those values are
supposed to move: an AHV number may legitimately go to the claims API and to the LLM
provider, but must never reach a third-party medical-coding service. The question is not
"did this value leave?" but "did this *class* of data reach a destination it was not
allowed to reach?".

The detection machinery is identical — the proxy already recognizes arbitrary literal
values through `PatternSet::with_canaries`, across the whole decoding chain. What is
missing is (a) a way to supply values from outside, (b) a class label to group them, and
(c) a per-value destination policy so an expected flow is *recorded* rather than blocked.

## Options Considered

### Option 1: Reuse `[[host]] allow_credentials` with a synthetic detector per class
**Description**: Register each data class as a DLP detector and let the existing
credential-scope table decide where it may flow.
**Pros**:
- One authorization concept; no new policy surface.
**Cons**:
- Detectors are regex patterns compiled at startup; a run with 50 generated values would
  mean 50 detectors, and the scope table is keyed by detector, not by value.
- Conflates "this credential may be used here" with "this data class may be seen here",
  which are different questions with different audiences.
**Estimated effort**: Medium

### Option 2: Per-canary data class and allow-list (chosen)
**Description**: A new recipe section and an equivalent per-run JSON file:

```toml
[[network.dlp.external_canaries]]
value = "CNRY-7Q2X-AHV"
data_class = "ahv"
allowed_hosts = ["claims.mock.internal", "api.anthropic.com"]
```

Values join the existing canary set for detection. On a hit, the proxy looks the value up:
reaching a host in `allowed_hosts` produces `canary_fire` with `allowed: true` and the
request proceeds; any other host is a leak — blocked outside monitor mode, always
recorded.
**Pros**:
- Detection reuses `PatternSet::with_canaries` and the whole decode chain unchanged.
- The policy reads exactly like the question being asked: "which destinations may see
  this class of data?"
- Values never enter the sandbox environment, so they cannot be discovered by the
  workload enumerating `CANISTER_CANARY_*`.
**Cons**:
- A second, canary-specific destination policy alongside `[[host]]` contracts.
**Estimated effort**: Low

### Option 3: Report only, never block
**Description**: External canaries are observational; the orchestrator decides.
**Pros**: No risk of breaking a run on a false positive.
**Cons**: The sandbox would knowingly forward personal data to a destination the operator
declared off-limits. Enforcement is the product's reason to exist; `--monitor` already
exists for the observational case.
**Estimated effort**: Low

## Decision

**Option 2**, with three ways in, all equivalent:

- `[[network.dlp.external_canaries]]` in a recipe (merged by `value`, last wins).
- `--canaries-file <path>`: a JSON array of the same shape, for per-run values an
  orchestrator generates.
- Directly on `ProxyServerConfig::with_external_canaries` for embedders.

Semantics, in `can-proxy/src/server/canaries.rs`:

| Situation | `canary_fire` | Request |
|---|---|---|
| Value reaches a host in its `allowed_hosts` (or a subdomain) | `allowed: true`, with `data_class` | proceeds, no `dlp_block` |
| Value reaches any other host | `allowed: false`, with `data_class` | blocked (451) |
| Same, under `--monitor` | `allowed: false` | proceeds, `dlp_block` records `blocked: false` |
| A generated tripwire canary fires | `allowed: false`, no `data_class` | blocked (unchanged) |

`canary_fire` gains `data_class`, `allowed` and `location`
(`header`/`path`/`query`/`body`/`trailer`/`response`), the last derived from the
scanner's existing `StringSource`. An empty `allowed_hosts` means the value may not leave
at all.

External canaries are **not** injected into the sandbox environment: they are planted in
the workload's input data by whoever generated it, and `can` only learns to recognize
them.

Detection requires DLP, which `egress = "proxy-only"` enables. Supplying canaries without
DLP logs a warning rather than silently turning scanning on — enabling DLP would activate
every other detector too, which is not what the caller asked for.

## Consequences

### Positive
- A run produces a data-flow record per data class, which is what a data-protection
  reviewer actually asks for.
- Expected flows are visible as evidence (`allowed: true`), not only violations.
- No new detection machinery: the decode chain, streaming scan and response scan all
  cover external canaries for free.

### Negative
- A value planted in data that the workload legitimately echoes to many destinations will
  fire often. That is the point, but it means `allowed_hosts` must be authored with care.
- Classification matches by value containment, so two canaries where one is a substring of
  the other would classify ambiguously. Generators should use fixed-length, distinct
  tokens.

### Neutral
- The counter behind `canary_fire_count` now includes allowed fires; consumers wanting
  leaks only filter on `allowed: false`.

## Follow-up Actions
- [ ] The orchestrator's generators emit values and the matching canaries file
      (the caller's, not `can`'s).
- [ ] Consider a `data_class` aware summary in `can`'s monitor-mode exit output.
