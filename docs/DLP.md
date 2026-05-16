# Data Loss Prevention (DLP)

Canister's L7 egress proxy includes a built-in DLP layer that scans
outbound HTTP traffic for credential patterns and enforces per-detector
domain scoping. Even when a sandboxed process has filesystem access to
credential files (because the user wants `npm`, `gh`, or `aws` to keep
working), DLP makes it structurally impossible for those credentials to
leak to unauthorised destinations.

## Table of Contents

- [Threat Model](#threat-model)
- [Architecture](#architecture)
- [Detectors and Scope Model](#detectors-and-scope-model)
- [Scan Pipeline](#scan-pipeline)
- [Encoding Chain Recursion](#encoding-chain-recursion)
- [Content Decompression](#content-decompression)
- [DNS Entropy Check](#dns-entropy-check)
- [Session Entropy Budget](#session-entropy-budget)
- [Canary Tokens](#canary-tokens)
- [Enforcement Modes (`--strict` and `--monitor`)](#enforcement-modes)
- [Response Headers and Status Codes](#response-headers-and-status-codes)
- [Configuration](#configuration)
- [Limitations](#limitations)

---

## Threat Model

A sandboxed process typically has filesystem access to credential-bearing
files — intentionally, because the user wants their package managers and
CLI tools to keep working against private registries. That process is
potentially:

- **Untrusted** — a build script, post-install hook, or LLM-generated
  command running with read access to `~/.npmrc`, `~/.aws/credentials`,
  the GitHub keyring, etc.
- **Trusted-but-buggy** — telemetry code that accidentally serialises
  environment variables containing tokens.
- **Trusted-but-compromised** — a supply-chain attack inside an
  otherwise reputable dependency.

DLP's goal: even when a credential is *readable*, it cannot leave the
sandbox via HTTP(S) unless flowing to an explicitly authorised
destination for that credential's service.

**In scope:**

- HTTP/1.1 and HTTP/2 request headers, bodies, trailers
- URI query parameters and path segments
- Bodies wrapped in gzip / deflate / brotli
- Multi-layer encoded payloads (base64 / hex / percent), up to 32 levels
- DNS-label exfiltration via high-entropy hostname labels
- Slow byte-at-a-time exfiltration via cumulative entropy budgeting

**Out of scope:**

- Covert timing channels
- In-memory key extraction
- Filesystem-write exfiltration to shared/CWD mounts
- Pixel-level steganography in image payloads
- Plain `CONNECT` (L4) tunnels — DLP forces interception when enabled,
  so any traffic that bypasses interception (e.g. non-HTTP protocols)
  is denied rather than inspected.

---

## Architecture

DLP lives in the standalone `can-dlp` crate so it can be reused by both
the proxy and the sandbox (for canary generation) without pulling proxy
dependencies into the sandbox crate.

```
crates/can-dlp/
  src/
    detectors.rs      — DetectorId enum, compiled RegexSet, Finding
    scopes.rs         — per-detector domain matching (built-in + extras)
    decode.rs         — base64/hex/percent recursion, up to N layers
    decompress.rs     — gzip/deflate/brotli body decompression
    normalize.rs      — whitespace/unicode normalisation before scanning
    entropy.rs        — Shannon entropy + SessionEntropyBudget
    canary.rs         — fake credential generation
    scanner.rs        — DlpScanner: orchestrates the full pipeline
    error.rs          — DlpError (thiserror)
```

The `DlpConfig` serde struct lives in `can-policy` (next to
`NetworkConfig`) to avoid a `can-dlp → can-policy` circular dependency.

Activation chain:

```
recipe / manifest [network.dlp]
        │
        ▼
NetworkConfig::dlp (Option<DlpConfig>)
        │
        ▼
ProxyServer constructed with DlpScanner + SessionEntropyBudget
        │
        ▼
Per-request: scan headers + URI + (decompressed, decoded) body
```

When DLP is enabled, the proxy **forces interception** of all traffic.
The passthrough path (which is opaque to the proxy) is disabled because
it would bypass scanning.

---

## Detectors and Scope Model

Each detector has hardcoded **home domains** baked into the binary.
Tokens can only flow to their home service — even if `allow_domains`
permits the destination, a GitHub PAT bound for `registry.npmjs.org` is
blocked.

| Detector | Pattern | Built-in home domains | Default action |
|---|---|---|---|
| `github_pat` | `gh[pousr]_[A-Za-z0-9]{36}` and `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}` | `github.com`, `*.github.com` | block |
| `npm_token` | `npm_[A-Za-z0-9]{36}` | `registry.npmjs.org` | block |
| `aws_access_key` | `AKIA[A-Z0-9]{16}` | `*.amazonaws.com` | block |
| `slack_token` | `xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}` | `*.slack.com` | block |
| `ssh_private_key` | `-----BEGIN (RSA\|EC\|OPENSSH\|DSA )?PRIVATE KEY-----` | *none — always block* | block |
| `bearer_token` | `Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*` | *(any `allow_domains` destination)* | block |
| `generic_high_entropy` | Sliding window, Shannon entropy > 4.5, 20+ chars | *(warn only)* | warn (promoted to block in `--strict`) |
| `canary_token` | Exact match against injected fake credentials | *none — always block* | block (error log) |

**Enforcement rules:**

1. **Known-service tokens** (`github_pat`, `npm_token`, `aws_access_key`,
   `slack_token`) — destination must be in the detector's home domains
   (plus any `extra_scopes` for self-hosted instances). Mismatched
   service → 451 block.
2. **`bearer_token`** — generic; allowed to any destination that already
   passes the `allow_domains` egress allow list. The proxy's domain
   allow list IS the scope.
3. **`ssh_private_key` and `canary_token`** — no legitimate HTTP
   destination; always blocked.
4. **`generic_high_entropy`** — too noisy to scope; always warn, blocks
   only in `--strict`.

This means tool recipes don't need any DLP-specific configuration. The
`allow_domains` in `tool:gh`, `tool:npm`, etc. already declares the
right egress destinations, and DLP knows which tokens belong where.
Composing `tools = ["npm", "gh"]` in a manifest produces the right
behaviour: npm tokens can only reach npmjs.org, GitHub PATs can only
reach GitHub — even though both domain sets are simultaneously in
`allow_domains`.

### Extending scopes for self-hosted services

Self-hosted services (GitHub Enterprise, private npm registries) extend
the built-in scopes via `extra_scopes`:

```toml
[network.dlp]
enabled = true

[network.dlp.extra_scopes]
github_pat = ["github.corp.example.com"]
npm_token = ["npm.internal.example.com"]
```

Extras are **unioned** with the built-in domains. They never replace or
narrow them, so a self-hosted override cannot accidentally weaken the
default scope for the public service.

---

## Scan Pipeline

Per request, the proxy runs:

```
1. Headers (Authorization, Cookie, Proxy-Authorization, X-*)
   → scan_text → token detected? scope check
2. URI (full reconstructed authority + path + query)
   → scan_text → token detected? scope check
3. Body
   a. Read Content-Encoding header
   b. Decompress (gzip / deflate / brotli) if configured
   c. Run encoding chain recursion (base64 / hex / percent)
   d. Pattern match each layer against PatternSet
4. For every finding:
   - canary    → BLOCK + error! log (zero false positives)
   - ssh key   → BLOCK
   - scoped    → BLOCK if destination not in home/extras
   - bearer    → BLOCK if destination not in allow_domains
   - generic   → WARN (BLOCK in --strict)
5. Session entropy budget update; BLOCK if exceeded.
6. Build response:
   - On allow: forward upstream with `update_content_length()` if body
     was buffered.
   - On block: 451 + `x-canister-error: dlp-blocked` +
     `x-canister-dlp-detector: <name>`.
   - On monitor-mode warn: forward upstream + add
     `x-canister-dlp-warning` so the sandboxed process can observe what
     would have been blocked.
```

DLP **forces request body buffering** within the existing
`max_buffered_body_bytes` cap. A streaming scan would miss tokens that
straddle chunk boundaries; the cap (default 8 MiB) prevents memory
abuse.

---

## Encoding Chain Recursion

`decode.rs` walks every layer of `base64 / base64url / hex /
percent-encoding` up to `max_decode_depth` (default 32). At each layer
the scanner attempts all decoders; any that produces output different
from its input is recursed into. **All decoded layers** are matched
against `PatternSet`, so:

- `Authorization: Bearer dGVzdA==` (`Bearer test`) is matched at the
  original layer.
- `body={"x":"Z2hwX0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="}` (a
  base64-wrapped GitHub PAT) is caught at depth 1.
- `base64(base64(token))` is caught at depth 2.
- Garbage / malformed encoding at any layer is **fail-closed**: the
  original bytes are scanned as-is and the recursion stops on that
  branch — never silently skipped.

The depth cap is a fuse against adversarially deep nesting designed to
exhaust CPU.

---

## Content Decompression

`decompress.rs` inspects the `Content-Encoding` header and inflates
`gzip` / `deflate` / `brotli` bodies before scanning. This is gated by
`network.dlp.decompress` (default `true`).

Malformed or truncated compressed bodies fail the request rather than
being forwarded unscanned — fail-closed.

---

## DNS Entropy Check

Independently of HTTP scanning, the proxy applies a Shannon-entropy
check to the *destination hostname* before resolving it. Each DNS label
(the parts between the dots) is scored; if any label exceeds
`dns_entropy_threshold` (default 4.5) the request is blocked with
`dlp-blocked` + `dns-entropy` reason. This catches the classic DNS
exfiltration pattern: `<base64-of-secret>.attacker.example` where the
high-entropy subdomain is the payload.

The check runs even on `CONNECT` tunnels (before resolution), so it
applies regardless of L7 protocol.

---

## Session Entropy Budget

A sandbox session keeps a `SessionEntropyBudget` (default 8192 bytes).
After each request scan, the count of high-entropy bytes (Shannon
entropy > 4.0 in any 32-byte sliding window) is recorded against the
budget. When the budget is exhausted, further requests are blocked.

This catches **slow exfiltration**: a credential split across many small
requests, each individually below the per-request entropy threshold but
collectively well above plausible legitimate traffic patterns.

The budget is per `ProxyServer` instance, which is one per sandbox
session — it resets when the sandbox exits.

---

## Canary Tokens

When `canary_tokens = true` (default when DLP is enabled), the sandbox
generates three fake credentials at startup and exports them as
environment variables into the sandboxed process:

| Env var | Shape |
|---|---|
| `CANISTER_CANARY_GITHUB_PAT` | `ghp_` + 36 random alphanumeric |
| `CANISTER_CANARY_NPM_TOKEN` | `npm_` + 36 random alphanumeric |
| `CANISTER_CANARY_AWS_ACCESS_KEY` | `AKIA` + 16 random uppercase |

The same exact strings are registered as the highest-priority pattern in
the `DlpScanner`. Any outbound appearance of one of these strings is
**proof of exfiltration** — no legitimate process produces these values,
because they don't authenticate to anything. The detection is always
`block` and is logged at `error!` level with full request context.

Canary tokens are an active honeypot: they create traffic that a
malicious process is incentivised to scoop up (env vars are the first
thing credential thieves enumerate) and which the proxy treats as a
high-confidence trip wire.

---

## Enforcement Modes

DLP integrates with the existing sandbox enforcement modes rather than
introducing a separate kill switch.

| Mode | DLP enabled? | `generic_high_entropy` | Block action |
|---|---|---|---|
| Default | Per recipe `enabled = true` | warn | 451 |
| `--monitor` | As configured | warn (logged) | **Not blocked** — request forwarded with `x-canister-dlp-warning` header |
| `--strict` | **Implicitly enabled** when `egress = "proxy-only"` | **promoted to block** | 451 |

- **Default**: DLP runs if the recipe enables it; violations are 451.
- **`--monitor`**: DLP findings are logged at `warn!` level with full
  detector / host / fingerprint detail but requests still go through.
  Mirrors how monitor mode handles seccomp and filesystem checks. Use
  this to dry-run a new policy before flipping it on.
- **`--strict`**: DLP is implicitly enabled even without
  `dlp.enabled = true`, provided the recipe uses `egress = "proxy-only"`
  (strict mode requires DLP-grade enforcement). `generic_high_entropy`
  is promoted from warn to block.

No new flags or kill switches were added — `--strict` plus recipe
config cover the same activation surface as a dedicated enable knob.

---

## Response Headers and Status Codes

| Outcome | Status | Headers |
|---|---|---|
| Token detected, blocked | `451 Unavailable For Legal Reasons` | `x-canister-error: dlp-blocked`, `x-canister-dlp-detector: <name>` |
| Token detected, monitor mode | (upstream status) | `x-canister-dlp-warning: <name>` |
| DNS-label entropy block | `451` | `x-canister-error: dlp-blocked`, `x-canister-dlp-reason: dns-entropy` |
| Session budget exhausted | `451` | `x-canister-error: dlp-blocked`, `x-canister-dlp-reason: session-budget` |

`451` is used so DLP blocks are distinguishable from upstream `403`s.
The detector name is exposed in the header so the sandboxed process /
calling tool can produce a sensible error message.

---

## Configuration

Full schema (all fields optional; defaults shown):

```toml
[network.dlp]
enabled = false                   # implicit true under --strict + proxy-only
canary_tokens = true              # default when DLP is enabled
max_decode_depth = 32             # encoding chain recursion cap
decompress = true                 # gzip/deflate/brotli before scan
dns_entropy_threshold = 4.5       # Shannon entropy per DNS label
session_entropy_budget = 8192     # cumulative high-entropy bytes/session

[network.dlp.extra_scopes]
github_pat = ["github.corp.example.com"]
npm_token = ["npm.internal.example.com"]
```

### Merge semantics

When recipes / manifests are merged left-to-right (`base.toml` →
auto-detected → explicit `-r` → manifest overrides), each field uses:

| Field | Merge rule | Rationale |
|---|---|---|
| `enabled` | OR (any `Some(true)` wins) | Security escalation, never reversed |
| `canary_tokens` | OR | Same |
| `extra_scopes` | per-detector domain union | Never narrows |
| `max_decode_depth` | last-Some-wins | Numeric tuning |
| `decompress` | last-Some-wins | |
| `dns_entropy_threshold` | last-Some-wins | |
| `session_entropy_budget` | last-Some-wins | |

This guarantees a downstream recipe can never *disable* DLP that an
upstream recipe enabled, and can never *shrink* the scope set.

### Where to put it

- **Project-level**: `[network.dlp]` in `canister.toml` enables DLP for
  every sandbox in the project.
- **Per-sandbox**: same key under `[sandbox.<name>.network.dlp]`.
- **Recipe-level**: drop a `[network.dlp]` block into a custom recipe.
  Tool recipes (`tool:gh`, `tool:npm`, etc.) deliberately do **not**
  ship DLP config — they only declare the right `allow_domains`, and
  DLP scopes do the rest.

---

## Limitations

- **Pattern coverage is finite.** A novel credential shape (a vendor
  introducing a new prefix) won't be caught until a detector is added.
  `generic_high_entropy` is the catch-all, but its `warn`-by-default
  posture means it's only fatal in `--strict`.
- **Body buffering ceiling.** Requests above `max_buffered_body_bytes`
  (default 8 MiB) are rejected with `413 Payload Too Large` rather than
  forwarded unscanned. This is fail-closed by design, but it limits the
  protocol shapes DLP can cover (large file uploads need a higher cap
  or a different egress path).
- **TLS interception is required.** DLP relies on the proxy's MITM CA;
  it does not inspect end-to-end-pinned TLS (e.g. when the sandboxed
  process pins its own cert). Such traffic fails to handshake under the
  proxy, which is the same fail-closed posture.
- **No regex on raw binary.** Detectors operate on UTF-8 text after
  decompression and decoding. Binary protocols carrying credentials
  outside text fields (e.g. proprietary RPC over HTTP) need a custom
  detector or a different egress strategy.
