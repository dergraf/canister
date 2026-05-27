# ADR-0008: Fake-Secret Swap for Env-Var Credentials

## Status
Proposed

## Date
2026-05-27

## Context

DLP (ADR-0007 and the `can-dlp` crate) is fundamentally a *detection*
layer: it buffers, decodes, and pattern-matches outbound bytes, blocking
a credential that flows to a host not authorised for it. This works well
for credentials in the clear, but it has a structural blind spot that no
amount of decoder investment closes: **a compromised worker can encrypt
a secret before exfiltrating it.** The ciphertext matches no detector,
and the attacker controls the encryption side of an asymmetric arms race.

For one important and common case — secrets supplied via environment
variables (`GITHUB_TOKEN`, `OPENAI_API_KEY`, …) — we can sidestep the
arms race entirely by attacking the root cause: if the sandbox never
holds the real secret, it has nothing real to encrypt.

The sandbox already injects pattern-matching **canary** tokens (honeypots
under `CANISTER_CANARY_*` names) that the proxy treats as tripwires. The
missing capability is a *functional* fake: one the real tool can carry,
that the proxy turns back into the real secret only for legitimate,
authorised destinations.

## Options Considered

### Option 1: Tie fakes to existing credential detectors; reuse scope as the swap gate
**Description**: A recipe marks an env var with a detector id
(`{ env = "GITHUB_TOKEN", credential = "github_pat" }`). The sandbox
gets a fake generated to match that detector's pattern; the proxy swaps
fake→real only where that detector is in scope (home domain or
`[[host]] allow_credentials`) — the exact check the scanner already uses
to downgrade a verdict.
**Pros**:
- Maximum reuse: fake generation reuses `CanarySpec`; the swap-authorisation
  gate reuses `DlpScopes::is_allowed`; exfil detection reuses the detector regex.
- One authorisation concept (`allow_credentials`), auditable in one place.
- Out-of-scope exfil is blocked *before* the swap point by the existing scanner.
**Cons**:
- Only covers secrets whose credential has a recognizable pattern.
**Estimated effort**: Low–Medium.

### Option 2: Opaque fakes + a per-secret `allow_hosts` list
**Description**: Generate an opaque random fake; detect exfil by exact
substring; gate the swap with a new per-secret host allow-list.
**Pros**: Supports patternless secrets.
**Cons**: Introduces a *second* authorisation mechanism parallel to
`allow_credentials`; weaker exfil detection (exact-substring only).
**Estimated effort**: Medium.

## Decision

**Option 1.** Each faked secret references an existing credential detector;
fake generation and swap authorisation both flow from that single detector
identity, reusing the scanner's scope table. Schema lives under
`[network.dlp]`:

```toml
[network.dlp]
fake_secrets = [{ env = "GITHUB_TOKEN", credential = "github_pat" }]
```

Mechanics:
- **Parent** (pre-fork, `can-sandbox`) captures the real host value,
  generates the fake (`can_dlp::generate_fake`), injects the fake under the
  real var name (stripping any passthrough copy so the real never enters the
  child), and hands the proxy a `fake → real` map.
- **Proxy** (`can-proxy`) swaps fake→real in request headers and the
  buffered body just before forwarding, **only** when the credential is
  authorised for the destination (`DlpScanner::credential_allowed`),
  checked independently of `--monitor` so monitor mode can never leak a
  real secret.

The swap is gated by the **same** `allow_credentials` / home-domain scope
the scanner uses — no new trust surface. `fake_secrets` is itself a
credential-trust escalation, so it is dropped from untrusted (unpinned)
recipes exactly like `allow_credentials`.

This ADR also fixes a pre-existing bug uncovered here: the load-time trust
gate keyed on `path.file_name()`, which never matched the relative-path
keys in `checksums.toml`, so nested service recipes' credential scope was
*always* dropped. The gate now matches on content-hash membership,
consistent with `can pull`'s relative-path verification.

The shipped service recipes (`github`, `npm-registry`, `openai`,
`anthropic`, `slack`, `stripe`) declare `fake_secrets` by default. AWS is
deferred (its secret-access-key has no detector pattern; see below).

## Consequences

### Positive
- The real value of a marked env-var secret never enters the sandbox's
  address space; encrypt-then-exfiltrate leaks only the useless fake.
- Legitimate tooling is unaffected — the proxy restores the real value
  transparently on authorised egress.
- Reuses generation, detection, and authorisation; the security-relevant
  surface stays auditable in one sitting.

### Negative
- Coverage limited to env-var secrets with a generatable detector pattern.
  Mitigation: adding a pattern is a one-line `CanarySpec` registry edit;
  Option 2 (opaque fakes) remains available as a future extension.
- Secrets in a streamed request body above the proxy's buffered-body cap
  aren't swapped (headers — the common case — always are). Documented.

### Neutral
- The honeypot canary set grows (one fake per detector with a `CanarySpec`);
  canaries and fake secrets remain distinct mechanisms.

## Follow-up Actions
- [ ] Opaque-fake path + per-secret `allow_hosts` for patternless secrets (Option 2).
- [ ] Symmetric AWS handling (`AWS_SECRET_ACCESS_KEY` has no pattern).
- [ ] Consider swapping URI query parameters (headers + body covered today).
