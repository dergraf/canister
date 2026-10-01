# ADR-0022: `[unsafe]` in the Resolved Policy

## Status
Accepted

## Date
2026-10-01

## Context

ADR-0014 put the resolved policy into the event stream as `policy_resolved`, with a
canonical hash, so that a run's evidence states the rules it ran under. ADR-0009 moved
every setting that lowers isolation into one `[unsafe]` block, so that a reviewer cannot
miss them.

The two did not meet. `[unsafe]` folds into the runtime `SandboxConfig` at resolve time,
and three of its switches land in fields that are deliberately `#[serde(skip)]` — the
skip is what makes `[network] allow_host_loopback` a parse error and forces authors into
`[unsafe]`:

| `[unsafe]` switch | Runtime field | In `policy_resolved` before this ADR |
|---|---|---|
| `unfiltered_egress` | `network.egress = "direct"` | indirectly |
| `seccomp_default_allow` | `syscalls.seccomp_mode = "deny-list"` | indirectly |
| `extra_syscalls` | merged into `syscalls.allow_extra` | indistinguishable from safe additions |
| `host_loopback` | `network.allow_host_loopback` (skipped) | **absent** |
| `reachable_ips` | `network.allow_ips` (skipped) | **absent** |
| `expose_ports` | `network.ports` (skipped) | **absent** |

So a run with `host_loopback = true` produced the same `policy_resolved` — and the same
`policy_sha256` — as the run without it. `can up --dry-run` printed the switch; the
evidence did not. The settings that weaken a sandbox most were exactly the ones a
consumer judging that sandbox could not see, and the hash that is supposed to say "these
two runs ran under the same rules" said so about two different sandboxes.

## Options Considered

### Option 1: Stop skipping the runtime fields
**Description**: Serialize `allow_ips`, `ports` and `allow_host_loopback` under
`network`.
**Pros**:
- No new key.
**Cons**:
- The skip is load-bearing on the deserialization side: `SandboxConfig` is also parsed,
  and lifting it reopens the authoring path ADR-0009 closed. Splitting serialize from
  deserialize per field works, but hides the quarantine in attribute details.
- The switches would be scattered across `network` again — the very thing ADR-0009
  removed for readers.
**Estimated effort**: Low

### Option 2: Add an `unsafe` object derived from the runtime policy (chosen)
**Description**: The event's `policy` document gains a top-level `unsafe` object with the
same six fields as the `[unsafe]` recipe block, computed from the resolved runtime
config.
**Pros**:
- A consumer finds every weakening in one place, under the name an author wrote it with.
- Derived from what the sandbox enforces, not from what a recipe said: it cannot
  disagree with the runtime, and it also covers weakenings that arrive another way, such
  as `--port` on the command line, which lands in the same runtime field as
  `expose_ports`.
- The authoring-side quarantine is untouched.
**Cons**:
- `unfiltered_egress`, `seccomp_default_allow` and `extra_syscalls` are now stated twice
  (once in their runtime form, once here). Accepted: the two are computed from the same
  fields and cannot drift.
**Estimated effort**: Low

### Option 3: Emit `unsafe` only when a switch is on
**Description**: As Option 2, but omit the key for a sandbox with nothing weakened.
**Pros**:
- `policy_sha256` stays the same for every policy without `[unsafe]`.
**Cons**:
- A missing key would mean either "nothing weakened" or "emitted by a `can` that did not
  report it", and a consumer cannot tell which. ADR-0014 already chose effective values
  over implicit defaults for this reason.
**Estimated effort**: Low

## Decision

**Option 2.** `policy_resolved.data.policy` gains a top-level `unsafe` object, always
present:

```json
"unsafe": {
  "unfiltered_egress": false,
  "reachable_ips": [],
  "host_loopback": true,
  "expose_ports": [{"host_ip": "127.0.0.1", "host_port": 8080, "container_port": 80, "protocol": "tcp"}],
  "seccomp_default_allow": false,
  "extra_syscalls": []
}
```

- The field names and value shapes are those of the `[unsafe]` recipe block
  (`UnsafeConfig`), so a reader who knows the recipe language knows this object.
- Values are read back from the resolved runtime config by `UnsafeConfig::in_effect`:
  `unfiltered_egress` is `egress == "direct"`, `seccomp_default_allow` is
  `seccomp_mode == "deny-list"`, `expose_ports` includes ports published with `--port`,
  and `extra_syscalls` is the subset of `allow_extra` in `DANGEROUS_SYSCALLS` — which
  `[syscalls] allow_extra` rejects, so only `[unsafe]` can have put them there.
- `unsafe` is part of the document `policy_sha256` covers; the canonicalization of
  ADR-0014 is unchanged.
- Schema v1 is unchanged: `policy` was always an open object, and adding a key to it is
  the additive change v1 allows. `can recipe show` keeps printing the runtime config as
  TOML without `unsafe`; the event's document is now that plus `unsafe`.

## Consequences

### Positive
- A run's evidence now records every isolation-weakening switch in effect, including the
  three it could not see before.
- `policy_sha256` distinguishes a sandbox from a weakened copy of it.

### Negative
- **Every `policy_sha256` changes once.** The key is present for every policy, so a
  config that has not changed at all hashes differently under a `can` with this change
  than under one without it. A consumer that fingerprints runs by `policy_sha256`, or
  compares it with a stored baseline, will see one apparent policy change at the upgrade
  and must re-baseline. Whether a stored event predates this change is visible: its
  `policy` has no `unsafe` key.

### Neutral
- `unfiltered_egress`, `seccomp_default_allow` and `extra_syscalls` appear twice in the
  document; consumers may read either form.

## Follow-up Actions
- [ ] `can up --dry-run` could print its `[unsafe]` section from `UnsafeConfig::in_effect`
      too, so the human view and the evidence share one derivation (and the dry run gains
      `extra_syscalls`, which it does not print today).
