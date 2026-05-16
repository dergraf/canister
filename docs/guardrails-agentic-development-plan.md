# Guardrails Plan for Agentic Development

This plan focuses on preventing regressions while we continue building the proxy feature set.

## Objectives

- Enforce quality/security criteria consistently in local and CI workflows.
- Detect policy drift between seccomp and proxy enforcement paths.
- Add measurable coverage gates and ratchet over time.

## PR 1: Tighten Existing CI Guardrails

### Scope

- Fix integration runner skip accounting in `tests/integration/run.sh`.
- Reduce default CI workflow permissions to least privilege.
- Ensure release/latest jobs depend on full integration gates (including VM jobs).

### Acceptance Criteria

- Skips are reported as skips, not passes.
- Release path cannot run if required integration jobs fail.
- CI remains green on `main`.

## PR 2: Coverage Guardrail

### Scope

- Add a dedicated coverage job in `.github/workflows/ci.yml` using `cargo-llvm-cov`.
- Produce `lcov.info` as build artifact.
- Enforce minimum line coverage threshold.
- Document local coverage command.

### Initial Threshold

- Start at 65% line coverage; ratchet upward over time.

### Acceptance Criteria

- CI fails when coverage drops below threshold.
- Coverage artifact is available in CI.
- Local repro command is documented.

## PR 3: Silent-Risk Prevention

### Scope

- Add CI guard for new `#[ignore]` tests unless allowlisted with `owner`, `reason`, and `expiry`.
- Add CI guard against `unwrap`/`expect`/`panic!` in non-test production paths (allowlist explicit exceptions only).
- Add `shellcheck` for `tests/integration/*.sh`.

### Acceptance Criteria

- New ignored tests require explicit metadata.
- Unsafe panic-style patterns are blocked in prod code.
- Integration shell scripts pass linting.

## PR 4: Security Invariant Test Suite (Proxy + Seccomp)

### Scope

- Add explicit invariants:
  - disallowed domain blocked via proxy path,
  - allowed domain succeeds,
  - direct disallowed IP blocked via seccomp path,
  - proxy and seccomp decisions stay aligned for same policy.
- Gate PRs on these invariants.

### Acceptance Criteria

- Prevents recurrence of domain-bypass regressions.
- Fails on policy drift between seccomp and proxy.

## PR 5: Unified Local Verify Command

### Scope

- Add `ci/verify.sh` (or `scripts/verify.sh`) to run all required checks:
  - `fmt`, `clippy`, workspace tests,
  - coverage gate,
  - shellcheck,
  - security invariant tests.
- Document one-command contributor workflow.

### Acceptance Criteria

- Single local command mirrors CI guardrails.
- Reduced local-vs-CI mismatch.

## Ongoing Proxy Feature Work (Parallel Track)

While guardrails are being added, continue proxy feature development with these non-negotiable checks:

- New proxy behavior must include integration tests (success + deny paths).
- Any policy-related change must include seccomp/proxy parity assertions.
- Regressions in outbound restrictions are release-blocking.

## Execution Order

1. PR 1 (quickest protection)
2. PR 2 (coverage baseline)
3. PR 4 (security invariants)
4. PR 3 (risk linting)
5. PR 5 (developer ergonomics)
