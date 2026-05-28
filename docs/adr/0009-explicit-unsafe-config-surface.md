# ADR-0009: Explicit, Honest Config Surface (`[unsafe]`, `read`/`write`, `exec`)

## Status
Proposed

## Date
2026-05-27

## Context

A recipe's security posture is *emergent*: it is assembled from `[filesystem]`,
`[network]`, `[process]`, `[syscalls]`, top-level `strict`, `[[host]]`, and
`[network.dlp]`, then layered through composition. Reading a single recipe tells
you little about what will actually run, and several anti-patterns made the gap
between intent and effect dangerous:

1. **Permissive-by-omission was inconsistent.** Omitting `egress`/`seccomp_mode`
   locked down; omitting `allow_execve` (`[]`) meant *exec anything*. Users
   could not assume "unset = safe."
2. **Names lied about effect.** `[filesystem] allow` was read-only while
   `allow_write` (the host-persisting one) sat beside it; `egress = "direct"`
   read like "allowed" but silently disabled DLP and the contract gate.
3. **Isolation-weakening knobs looked ordinary.** `egress = "direct"`,
   `allow_ips`, `allow_host_loopback`, `ports`, `seccomp_mode = "deny-list"`,
   and dangerous `allow_extra` syscalls (`ptrace`, `bpf`, `io_uring_*`) were
   scattered across normal sections with no signal of their blast radius.
4. **Silent degradation.** Contradictory/inert config (e.g. credential scope
   with no proxy) was accepted with at most a log line.

Canister has no users yet and explicitly permits breaking changes, so this is
the moment to fix the config *language*, not paper over it with tooling.

## Decision

Adopt one principle — **isolation is the floor; every line that lowers it is
named for its cost and quarantined where a reviewer can't miss it** (Rust's
`unsafe`, applied to policy) — via four schema changes:

1. **`[unsafe]` block.** All isolation-weakening knobs move here and are
   **rejected anywhere else** (`serde(skip)` + `deny_unknown_fields`):
   `unfiltered_egress` (was `egress = "direct"`), `reachable_ips` (was
   `allow_ips`), `host_loopback`, `expose_ports` (was `ports`),
   `seccomp_default_allow` (was `seccomp_mode = "deny-list"`), and
   `extra_syscalls` (the high-risk subset of `allow_extra`). A recipe with no
   `[unsafe]` block provably cannot weaken the baseline; `grep -rL '\[unsafe\]'
   recipes/` is the audited-safe set. At resolve time these fold back into the
   runtime `NetworkConfig`/`SyscallConfig`, so the runtime is unchanged.

2. **Honest filesystem names:** `allow`→`read`, `allow_write`→`write`.

3. **Explicit `exec`:** `allow_execve` (empty = any) → `exec = "any" |
   "entrypoint-only" | [paths]`. An empty intent is now *stated*, not implied.

4. **Honest egress:** `egress` is `none | proxy` (was `proxy-only`); the
   unfiltered third mode is `[unsafe] unfiltered_egress`.

Supporting validations: a curated `DANGEROUS_SYSCALLS` registry rejects
high-risk syscalls from `[syscalls] allow_extra`; `egress = "direct"` in
`[network]` is rejected with a pointer to `[unsafe]`; and declaring
`unfiltered_egress` alongside DLP/`fake_secrets`/`allow_credentials` is a
parse error (they are inert without the proxy). `[unsafe]` is dropped from
*untrusted* recipes, like `allow_credentials` — project-specific weakenings
belong in the trusted `canister.toml` (`[sandbox.<name>.unsafe]`).

## Consequences

### Positive
- The blast radius of a recipe is visible at authoring time and greppable in
  review; `can` can surface a one-line `⚠ unsafe` summary at runtime.
- The "unset = safe" rule now holds uniformly; the one default-open knob
  (`allow_execve = []`) is gone.
- Field names match effects; contradictory/inert config fails loudly.
- Reuses the existing trust gate and merge semantics; the resolved
  `SandboxConfig` and all runtime consumers keep their shape.

### Negative
- Breaking change to every recipe and to the manifest schema (no back-compat
  shim, by choice). All shipped recipes + `checksums.toml` migrated in this
  change; `generic-strict`/`elixir`/`neovim` now carry an `[unsafe]` block for
  their `ptrace`/`io_uring` needs — which is the point: "strict" no longer
  silently widens the kernel surface.
- `entrypoint-only` exec is recorded but not yet fully enforced for child
  execs (needs the USER_NOTIF supervisor; the initial command is validated).

### Neutral
- `DANGEROUS_SYSCALLS` is a curated judgement list — a small, auditable
  registry expected to grow.

## Follow-up Actions
- [ ] Closeable composition (a `deny`-wins operator for every set) + merge
      provenance, paired with a resolved "security posture" report.
- [ ] Enforce `entrypoint-only` child-exec denial via the notifier.
- [ ] A declarative risk-label table driving the posture report and docs.
