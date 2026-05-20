# ADR-0007: Per-destination Egress Contracts

## Status
Proposed

## Date
2026-05-19

## Context

DLP today is a pure inbound-string filter: every request is buffered,
decoded, and pattern-matched. We've invested heavily in that path
(declarative transform registry, structured walkers for JSON / form /
multipart / XML, trailer scanning, proptest harness over 21 channels)
and it works well for what it does. But it has a structural ceiling:

- The attacker controls the *encoding* side. We respond by adding
  more decoders. They add another layer. We add another. This is an
  asymmetric arms race — the encoding space is infinite, the decoder
  budget is not.
- We can't reach pixel data inside a PNG, payload inside a protobuf,
  or steganographic LSB-encoding. A compromised worker that
  base64-encodes `~/.ssh/id_ed25519`, wraps it as a PNG, and
  `POST`s the result to `https://api.github.com/repos/foo/issues`
  passes DLP cleanly — the bytes carry no credential-shaped strings.
- We have no way to express "this host doesn't legitimately receive
  binary uploads at all." Yet for almost every upstream a worker
  legitimately talks to (`api.github.com`, `registry.npmjs.org`,
  `api.openai.com`, …) the legitimate request shape is narrow and
  known: JSON, specific methods, modest body size. Anything else is
  prima facie suspicious independent of content.

Behaviour gating before content scanning would close the structural
gap. The design question is **not** whether to add it — that's almost
obvious — but how to make it a *usable* feature in a sandbox whose
brand is "simple for non-expert users." Any contract we ship will be
wrong for some workload. If "wrong contract" translates to "worker
silently broken with a 415 and no path forward," we've made the
product worse. The override surface IS the product.

## Options Considered

### Option 1: Status quo — DLP scan only

**Description**: Don't add behaviour gates. Keep iterating on
decoders, walkers, normalisers.

**Pros**:
- Zero new configuration surface.
- No risk of false-positive refusals on legitimate traffic.

**Cons**:
- The structural ceiling described above remains.
- Each new exfil format we want to catch (PNG metadata, ZIP comments,
  PDF `/Info`) requires writing a new walker.
- Steganography and dense-binary payloads stay permanently
  out-of-scope.

**Estimated effort**: Zero (continue current trajectory).

### Option 2: Per-destination egress contracts in recipes (proposed)

**Description**: A new `[[network.host_contract]]` recipe section
declares, per FQDN (or wildcard), the legitimate request shape:
allowed methods, allowed Content-Types, max body size, optional path
prefixes. The proxy gates inbound requests against the resolved
contract *before* the DLP scan runs. Refusals carry an actionable
error response that includes the exact recipe patch needed to allow
the request. Contracts slot into the existing recipe merge chain
(base → service-detected → user-global → project-local → CLI), with
additive (union) semantics so later layers can only relax, never
silently tighten.

**Pros**:
- Closes the "PNG to api.github.com" class of attack independent of
  what's inside the PNG.
- Cuts the DLP scan's workload — refused requests never reach the
  decoder chain.
- Reuses the existing recipe layering, merge rules, and CLI
  surface. No parallel config system.
- Actionable error responses make refusals self-documenting; a
  novice user pastes 3 lines into `canister.toml` to unblock
  themselves without reading docs.
- Composes cleanly with the existing `[[dlp.scopes]]` table — a
  contract says "this host accepts JSON of this shape," scopes say
  "this host is allowed to receive `github_pat`s in that JSON."

**Cons**:
- We have to author and maintain service contracts for the top ~50
  upstreams. Services change their APIs; contracts will drift and
  need updates.
- A too-tight default ships breakage to a long tail of users. The
  "learn" mode and additive-only merge mitigate but don't eliminate
  this.
- Adds a new refusal path the user has to understand (415-class
  vs 451 DLP block). The error response and a single docs page
  must make the distinction obvious.

**Estimated effort**: Medium. Schema + merge ~1 day; gate
enforcement in `dlp_enforce` neighbourhood ~1 day; shipped service
contracts for the top 10 services ~1 day; actionable refusal
response ~0.5 day; tests + integration tests ~1 day.

### Option 3: Hard-coded service contracts in source

**Description**: Bake contracts into `crates/can-policy` as a
`&'static` table keyed by FQDN. No recipe-level override; users
adjust by patching the source and rebuilding.

**Pros**:
- Trivial implementation. No config surface to design.
- Single source of truth for what each service accepts.

**Cons**:
- Defeats the entire point of the user's concern: a non-expert who
  hits a refusal has no recourse short of recompiling `can`.
- Contracts can't be shared between users or pinned per project.
- Disqualified by the project's "simple to use by a non-expert"
  brief.

**Estimated effort**: Low — but the wrong direction.

### Option 4: CLI flag only (`--allow host:content-type`)

**Description**: No recipe-level contracts. Refusals are unlocked
exclusively via per-invocation `can run --allow …` flags.

**Pros**:
- Simplest possible mental model: refusal → add a flag.
- Per-invocation scope, no risk of accidentally relaxing security
  globally.

**Cons**:
- Doesn't compose with project teams: every `make` target, every CI
  script, every `python script.py` invocation has to repeat the
  flags.
- No way for an operator to ship sensible defaults to a team.
- Encourages "just throw `--allow-all` at it," defeating the purpose.

**Estimated effort**: Low. But insufficient on its own.

## Decision

**Option 2**, with Option 4 retained as a one-shot escape hatch on
the CLI. **Four** refinements over the originally proposed shape:

1. **Strict is the default mode.** No `Learn` mode.
2. **Schema collapses `[dlp.scopes]` and the proposed
   `[[network.host_contract]]` into a single per-host table**
   (`[[host]]`). Co-located because they answer adjacent questions
   about the same upstream — "what shape of request is legitimate"
   and "what credentials are legitimate to carry in that shape" —
   and forcing the user to keep them in sync across two sections
   was always going to invite drift.
3. **`[[host]]` also subsumes `allow_domains`.** A `[[host]]` block
   is the *only* way to permit egress to an FQDN. The minimum block
   is one field (`domain = "x"`). Eliminates the entire class of
   drift bugs where `allow_domains` and a separate contracts section
   could disagree about what's permitted: "allowed but uncontracted"
   and "contracted but unallowed" both become unrepresentable. A
   reviewer reads one list top-down to see the full egress posture.
4. **`contract_mode` is overridable per `[[host]]`.** Global default
   is `Strict`; a single weird upstream can opt itself to `Relaxed`
   without flipping the whole recipe. Inverse also works: a recipe
   running in `Relaxed` global mode can mark one host as `Strict`.

The shape:

### Unified per-host schema

```toml
[network]
egress         = "proxy-only"
contract_mode  = "strict"           # global default; can be overridden per [[host]]
allow_ips      = []                 # IP-literal egress, separate concept (no FQDN)

# Minimum-viable allow: just the domain, defaults for everything else.
[[host]]
domain = "static.example.com"

# Full picture for a service we care about.
[[host]]
domain             = "api.github.com"             # FQDN; "*.github.com" wildcards supported
methods            = ["GET", "POST", "PATCH", "PUT", "DELETE"]
content_types      = ["application/json", "application/vnd.github+json"]
max_request_bytes  = 1_048_576                    # 1 MiB
paths              = ["/repos/", "/user/", "/orgs/"]   # optional path-prefix restriction
allow_credentials  = ["github_pat"]               # replaces [dlp.scopes].github_pat

# Per-host escape hatch: this one weird internal tool isn't shape-gated.
[[host]]
domain        = "weird-tool.corp.internal"
contract_mode = "relaxed"
```

**A `[[host]]` block is the only way to permit egress to an FQDN.**
There is no separate `allow_domains` list. The minimum block
(`domain = "x"`) permits any method, any content type, any path,
any size, with no credential whitelist — equivalent to the old
`allow_domains = ["x"]` semantics. Anything tighter is opt-in
through additional fields on the same block.

`[dlp.scopes]` is removed alongside `allow_domains` — alpha, no
back-compat shim. Today's

```toml
[network]
allow_domains = ["github.com", "*.github.com", "registry.npmjs.org"]

[dlp.scopes]
github_pat = ["github.com", "*.github.com"]
npm_token  = ["registry.npmjs.org"]
```

becomes:

```toml
[[host]]
domain            = "*.github.com"
allow_credentials = ["github_pat"]

[[host]]
domain            = "github.com"
allow_credentials = ["github_pat"]

[[host]]
domain            = "registry.npmjs.org"
allow_credentials = ["npm_token"]
```

Two lists become one list. A security reviewer reads top-down per
upstream — connect permission, request shape, credential scope,
and any per-host mode override all in the same block.

Multiple `[[host]]` entries matching the same FQDN merge under the
existing `RecipeFile::merge` rules: union for vec fields, max for
`max_request_bytes`, last-Some-wins for `contract_mode`. A
project-local recipe can therefore extend (never silently restrict)
a canister-shipped contract:

```toml
# ./canister.toml — this project also uploads release assets.
[[host]]
domain            = "uploads.github.com"
methods           = ["POST"]
content_types     = ["application/octet-stream"]
max_request_bytes = 104_857_600                   # 100 MiB
```

`allow_ips` stays a separate top-level list under `[network]`: IP
literals have no FQDN, no service identity, and the per-route
shape gates don't sensibly apply to "an IP we connect to." Two
concepts, but distinct *kinds* of concept — not two parallel lists
of the same thing.

### Two modes for unknown hosts

`NetworkConfig::contract_mode: ContractMode` sets the global
default; each `[[host]]` block can override it via a `contract_mode`
field.

- **`Strict`** (global default) — hosts without a `[[host]]` entry
  are refused with the actionable error response. Forces explicit
  intent for every upstream a worker reaches. Matches the project's
  security brand (default-deny seccomp, default-deny network).
  In strict mode, refused requests never reach the DLP scanner.
- **`Relaxed`** — hosts without a `[[host]]` entry are allowed but
  every request emits a structured `unknown_host_contract` event.
  Exists as an opt-in for prototyping / exploratory workflows where
  the set of upstreams isn't known up front. The DLP scanner still
  runs as the secondary defence.

The per-host override means a strict recipe can carve out one
known-weird upstream as relaxed, and vice versa, without flipping
the global posture. Reading order, top to bottom: a reviewer sees
the global default in `[network]`, then any per-host deviations
in the `[[host]]` blocks themselves.

No `Learn` mode. The same outcome — figuring out what shape a
worker actually sends — is achievable by running once with
`Relaxed`, reading the `unknown_host_contract` event stream, and
hand-writing `[[host]]` entries from it. That's a one-screen
workflow and doesn't require us to maintain a runtime that
mutates the user's config file.

### Actionable refusal response

Every contract-refused request returns the patch:

```
HTTP/1.1 415 Refused by canister
x-canister-error: content-type-not-allowed
x-canister-host: api.github.com
x-canister-attempted-content-type: image/png
x-canister-doc: https://canister.dev/refusals/content-type-not-allowed

Refused: api.github.com does not accept Content-Type 'image/png'
under the active contract. Allowed: application/json,
application/vnd.github+json.

To allow this for the current project, append to ./canister.toml:

    [[network.host_contract]]
    domain        = "api.github.com"
    content_types = ["image/png"]   # extends the shipped contract

One-shot: can run --allow "api.github.com:image/png" -- ...
```

The same shape applies to method, size, and path refusals — the
distinguishing detail goes into the body and the
`x-canister-attempted-*` header so log scrapers can pivot on it.

### Enforcement order

```
gate by policy (allow_domains)              ← existing
gate by host contract (NEW)                 ← refuse here before any scan
DLP scan (headers, URI, body, trailers)    ← existing
forward upstream                            ← existing
DLP scan response                           ← existing
```

A contract refusal never reaches the DLP scanner, so the
combinatorial cost of "decode chain × structured walkers × scan
buffer" is paid only for requests that pass the cheap shape gate.
This is a CPU win in addition to a security win.

### Shipped `[[host]]` blocks

The first wave ships per-service contracts for the upstreams workers
most commonly hit. Each carries the full picture: shape gates plus
`allow_credentials`.

| Service              | Methods                | CTs                                    | `allow_credentials`   |
| -------------------- | ---------------------- | -------------------------------------- | --------------------- |
| `*.github.com`       | GET POST PATCH PUT DELETE | `application/json`, `application/vnd.github+json` | `github_pat`          |
| `uploads.github.com` | POST                   | `application/octet-stream`             | `github_pat`          |
| `api.openai.com`     | GET POST DELETE        | `application/json`, `multipart/form-data` | `openai_key`          |
| `api.anthropic.com`  | GET POST               | `application/json`                     | `anthropic_key`       |
| `registry.npmjs.org` | GET PUT                | `application/json`, `application/octet-stream` | `npm_token`           |
| `pypi.org`, `*.pythonhosted.org` | GET POST   | `application/json`, `multipart/form-data` | (none — `twine` uses HTTP basic auth, not a typed token) |
| `huggingface.co`     | GET POST PUT           | `application/json`, `multipart/form-data`, `application/x-www-form-urlencoded` | (HF token isn't in the detector registry yet) |
| `hub.docker.com`     | GET POST PUT PATCH     | `application/json`, `application/vnd.docker.*` | (no shipped detector) |
| `*.amazonaws.com`    | GET POST PUT DELETE    | `application/x-amz-json-1.1`, `application/xml`, `application/octet-stream` | `aws_access_key` |
| `*.stripe.com`       | GET POST DELETE        | `application/x-www-form-urlencoded`, `application/json` | `stripe_key` |

Each block is one file under `recipes/services/<name>.toml`,
embedded via `include_str!` the same way `base.toml` and
`default.toml` are. Auto-loaded when the resolved upstream matches.
Services for which we don't yet ship a detector get a contract
without `allow_credentials` — the shape gate still works, the
credential gate is a no-op until a detector lands.

## Consequences

### Positive

- A whole class of exfil attacks (binary upload to a JSON-only API,
  oversized PUT, suspicious method) is refused before the DLP
  scanner runs.
- The "I encoded the credential in PNG metadata" attack costs the
  attacker an `api.github.com → image/png` allowance they have to
  obtain explicitly — which leaves an auditable refusal event in
  the default `Strict` mode.
- DLP scan cost drops — refused requests skip the decoder chain.
- **Single source of truth for FQDN egress.** Three pre-existing
  concepts (`allow_domains`, the proposed `host_contract`,
  `[dlp.scopes]`) collapse into one `[[host]]` list. The reviewer
  reads one list top-down; the recipe author edits one block per
  upstream; the runtime resolves one structure. The
  "allowed-but-uncontracted" and "contracted-but-unallowed" drift
  bugs become unrepresentable rather than validated-against.
- Per-host `contract_mode` override means a globally-strict recipe
  doesn't need to be globally-relaxed just because one weird
  internal tool exists.
- Refusal responses carry their own remediation patch; project
  teams pin contracts in the repo-checked `canister.toml`; one-shot
  CLI escape exists for ad-hoc debugging.
- Strict-by-default matches the rest of the project's posture
  (default-deny seccomp, default-deny network) — no surprising
  asymmetry where "egress shape" is more permissive than "egress
  destination."

### Negative

- We commit to maintaining a service-contract registry. APIs change
  (GitHub adds a new endpoint that requires `Content-Type: text/csv`,
  npm switches from JSON to gRPC, …) and our contracts drift. The
  mitigations are layered: shipped contracts use *additive*-only
  merge so project recipes can extend without us shipping a release;
  the refusal response shows the exact patch; the `Relaxed` opt-in
  (global or per-host) is the escape hatch when a worker hits an
  unknown shape in a prototype.
- Strict-by-default ships first-run friction. A user running
  `can run -- python script.py` against a host we don't ship a
  contract for gets refused on the first request. The refusal
  response shows the patch, but it's still a stop-the-world
  moment. Trade we're choosing to make for the security posture.
- The "minimum to allow a host" goes from
  `allow_domains = ["x"]` (one comma-separated entry) to
  `[[host]]\ndomain = "x"` (two lines). Real ergonomic regression
  for the throwaway case. Accepting it because it kills the
  two-list drift class that hurts most in security configs.
- Two refusal classes (415 contract / 451 DLP) increase the
  surface a user has to learn. A single `docs/refusals.md` page
  must make the distinction obvious; the `x-canister-error`
  header carries the disambiguator for log pipelines.
- Existing recipes need to migrate `allow_domains` *and*
  `[dlp.scopes]` into per-host `[[host]]` blocks. Alpha, no shim —
  the strict TOML parser will emit `unknown field allow_domains` /
  `unknown field dlp.scopes` errors pointing at the offending file
  and line.

### Neutral

- One concept (`[[host]]`) now does what three did. The docs need
  one section that explains the block's fields and walks through
  the "minimum allow" / "shape-gated allow" / "credential-scoped
  allow" progression — getting that explanation right is more
  important than the schema itself.
- `[[host]]` is a *top-level* table (not under `[network]` or
  `[dlp]`) precisely because it spans both. A small asymmetry with
  the rest of the schema where most tables live under
  `[network]`, `[dlp]`, `[mounts]`. We considered
  `[[network.host]]` and rejected it because the `allow_credentials`
  field is conceptually `[dlp]`-shaped, not `[network]`-shaped.
- `allow_ips` stays under `[network]` as a separate list. IP
  literals have no service identity, so per-route shape gates
  don't apply. Distinct concept, distinct schema.
- Wildcard matching (`*.github.com`) inherits the most-specific-wins
  precedence we already use for `allow_domains`.

## Follow-up Actions

- [ ] Add the `[[host]]` top-level schema in
      `crates/can-policy/src/config/host.rs` with
      `serde(deny_unknown_fields)`, matching the existing strict
      parsing. Field set: `domain`, `methods`, `content_types`,
      `paths`, `max_request_bytes`, `allow_credentials`,
      `contract_mode`.
- [ ] Add `ContractMode { Strict, Relaxed }` to `NetworkConfig`
      (global default, defaults to `Strict`) and as an optional
      override on each `[[host]]` block.
- [ ] **Remove** `NetworkConfig::allow_domains` entirely. Migrate
      shipped recipes (`recipes/base.toml`, `recipes/default.toml`,
      `recipes/*.toml`) to express their domain allow-list as
      minimum-viable `[[host]]` blocks.
- [ ] **Remove** `[dlp.scopes]` and `DlpScopes`. Migrate the
      `streaming_verdict` / `evaluate_finding` scope lookup to
      consult the resolved `[[host]]` block's `allow_credentials`.
- [ ] Extend `RecipeFile::merge` to union `[[host]]` entries by
      `domain` key; union vec fields, max for `max_request_bytes`,
      last-Some-wins for `contract_mode`.
- [ ] Add the contract gate in `crates/can-proxy/src/server/request.rs`
      between `gate_by_policy` (renamed: now host-resolve) and
      `scan_headers_and_uri`.
- [ ] Extend `ProxyError` with a `ContractRefused { reason, host,
      attempted, allowed, patch }` variant that emits the actionable
      response body.
- [ ] Author the first 10 `[[host]]` blocks (see table above) under
      `recipes/services/`.
- [ ] Add proptest channels for `disallowed_method` /
      `disallowed_content_type` / `oversize_body` / `unknown_host`
      and assert each produces a contract refusal (not a DLP scan).
- [ ] Write `docs/refusals.md` with the 415-vs-451 distinction and a
      "how do I unblock myself?" walkthrough.
- [ ] Update `docs/CONFIGURATION.md` and `CLAUDE.md` to describe the
      single `[[host]]` model and remove references to
      `allow_domains` and `[dlp.scopes]`. Include a "minimum-viable
      allow / shape-gated allow / credential-scoped allow"
      progression.
