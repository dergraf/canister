# Configuration Reference

Canister uses TOML configuration files with strict schema validation. Unknown
fields are rejected at parse time.

When no config file is provided (`can run -- command`), default policy uses
**proxy egress** with strict filesystem defaults and the default seccomp baseline.

## Table of Contents

- [Project Manifest (canister.toml)](#project-manifest-canistertoml)
  - [Manifest Format](#manifest-format)
  - [can up](#can-up)
  - [Dry-Run Preview](#dry-run-preview)
  - [Composition Order (can up)](#composition-order-can-up)
- [Recipe Composition](#recipe-composition)
  - [Merge Semantics](#merge-semantics)
  - [Name-Based Lookup](#name-based-lookup)
  - [Auto-Detection via match_prefix](#auto-detection-via-match_prefix)
  - [Environment Variable Expansion](#environment-variable-expansion)
- [recipe (metadata)](#recipe-metadata)
- [filesystem](#filesystem)
- [network](#network)
- [[host]](#host)
- [network.dlp](#networkdlp)
- [process](#process)
- [resources](#resources)
- [syscalls](#syscalls)
- [unsafe](#unsafe)
- [proxy](#proxy)
- [Strict Mode](#strict-mode)
- [Monitor Mode](#monitor-mode)
- [Inspecting the Resolved Policy](#inspecting-the-resolved-policy)
- [Examples](#examples)

---

## Project Manifest (`canister.toml`)

A project manifest declares **named sandboxes** for a project. Instead of
remembering which `-r` flags to pass, you define sandboxes once in
`canister.toml` and run them with `can up`.

Place `canister.toml` in your project root (next to `.git/`). Canister
discovers it by walking up from the current directory, similar to `.gitignore`.

### Manifest Format

```toml
[sandbox.dev]
description = "Neovim + Elixir development"
recipes = ["neovim", "elixir", "nix"]
command = "nvim"

[sandbox.dev.filesystem]
write = ["$HOME/.local/share/nvim"]

[[sandbox.dev.host]]
domain = "api.myproject.dev"

[sandbox.test]
description = "Mix test runner"
recipes = ["elixir", "nix"]
command = "mix test"

[sandbox.ci]
description = "CI — strict, no network"
recipes = ["elixir", "nix", "generic-strict"]
command = "mix test --cover"
strict = true

[sandbox.ci.resources]
memory_mb = 2048
cpu_percent = 100
```

**`[sandbox.<name>]` fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | `string` | No | Human-readable description |
| `recipes` | `string[]` | **Yes** | Recipe names to compose (resolved via recipe search path) |
| `command` | `string` | **Yes** | Command to run (may include arguments) |
| `strict` | `bool` | No | Override strict mode for this sandbox |

**Override sections:**

Each sandbox can include optional override sections that merge on top of the
composed recipes. These use the same schema as recipe files:

- `[sandbox.<name>.filesystem]` — `read`, `write`, `deny`
- `[sandbox.<name>.network]` — `egress` (`none`/`proxy`), `contract_mode`
- `[[sandbox.<name>.host]]` — one or more per-destination contracts (see [`[[host]]`](#host) below)
- `[sandbox.<name>.process]` — `max_pids`, `exec`, `env_passthrough`
- `[sandbox.<name>.resources]` — `memory_mb`, `cpu_percent`
- `[sandbox.<name>.syscalls]` — `allow_extra`, `deny_extra`, `notifier`
- `[sandbox.<name>.unsafe]` — isolation-weakening knobs (see [`[unsafe]`](#unsafe)); the manifest is the trusted place to opt into these

Overrides follow the same [merge semantics](#merge-semantics) as recipe
composition: Vec fields are unioned, scalar fields use last-Some-wins,
strict uses OR.

**Validation rules:**

- At least one `[sandbox.<name>]` must be defined.
- Each sandbox must have `recipes = [...]` with at least one entry.
- Each sandbox must have a non-empty `command`.
- Unknown fields are rejected (`deny_unknown_fields`).
- Mixing absolute (`allow`/`deny`) and relative (`allow_extra`/`deny_extra`)
  syscall fields in a sandbox's `[syscalls]` section is an error.

### `can up`

Run a named sandbox from the manifest:

```bash
# Run the default sandbox (alphabetically first).
can up

# Run a specific sandbox by name.
can up dev
can up test
can up ci

# With CLI overrides.
can up dev --strict
can up dev --monitor
can up test -p 4000:4000
```

**Default sandbox:** When no name is given, `can up` uses the alphabetically
first sandbox. Use descriptive names so the default is predictable (e.g.,
`dev` sorts before `test`).

**Error handling:** If `canister.toml` is not found, `can up` prints an error
suggesting `can run` for ad-hoc use. If the named sandbox doesn't exist, it
lists available sandbox names.

### Dry-Run Preview

Use `--dry-run` to see the fully resolved policy without running anything:

```bash
can up dev --dry-run
can up ci --dry-run
```

The output shows the merged result of `base.toml` + auto-detected recipes +
manifest recipes + manifest overrides, including filesystem paths, network
domains, syscall overrides, and resource limits.

### Composition Order (`can up`)

```
base.toml
  → auto-detected recipes (match_prefix against command binary)
  → recipes listed in manifest (left to right)
  → manifest overrides ([sandbox.<name>.filesystem], etc.)
  = final SandboxConfig
```

This is the same merge chain as `can run`, except the explicit `-r` flags
are replaced by the manifest's `recipes = [...]` list, and manifest
overrides act as the final layer.

**Design note:** Package manager recipes (nix, homebrew, etc.) should be
listed explicitly in `recipes = [...]`. While auto-detection via
`match_prefix` still works for the command binary, explicit declaration
preserves the principle of least privilege — auditors can see exactly
which recipes are composed by reading `canister.toml`.

---

## Recipe Composition

Canister supports composing multiple recipes via repeated `-r` / `--recipe`
flags. Recipes are merged left-to-right into a single resolved config.

**Composition order:** `base.toml` → auto-detected recipes → explicit `--recipe` args.

`base.toml` provides essential OS bind mounts and is always loaded first
(embedded in the binary, overridable on disk). Auto-detected recipes are
matched by `match_prefix` before explicit recipes are applied. The
`default.toml` seccomp baseline is resolved separately by the seccomp module
and is NOT part of this composition chain.

```bash
# base.toml (always) → nix.toml (auto-detected) → elixir.toml (explicit)
can run -r elixir -- mix test    # mix resolves to /nix/store/..., nix.toml auto-detected

# Explicit composition
can run -r nix -r elixir -- mix test
can run -r cargo -r generic-strict -- cargo build
```

### Merge Semantics

When multiple recipes are merged, each field type follows a specific strategy:

| Field type | Strategy | Example |
|---|---|---|
| `Vec` fields (paths, domains, syscalls, env vars) | **Union** — deduplicated, order preserved | Two recipes allowing `/a` and `/b` → `["/a", "/b"]` |
| `strict` (`Option<bool>`) | **OR** — any `Some(true)` wins, can never be loosened | Recipe A: `strict = true`, Recipe B: omitted → `true` |
| `egress` (`Option<EgressMode>`) | **Last-Some-wins** — `None` preserves earlier value | Recipe A: `egress = "none"`, Recipe B: `egress = "proxy"` → `proxy` |
| `[unsafe]` fields (bools / vecs) | **OR / union** — security-monotonic, a weakening in any layer stays | Recipe A: `host_loopback = true`, Recipe B: omitted → `true` |
| Numeric (`max_pids`, `memory_mb`, `cpu_percent`) | **Last-Some-wins** | Recipe A: `max_pids = 64`, Recipe B: `max_pids = 128` → `128` |
| `RecipeMeta` | **Overlay** — later recipe's metadata wins if present | — |

The "last-Some-wins" strategy means `None` (field not specified) preserves
the value from an earlier recipe, while `Some(value)` overwrites it.

### Name-Based Lookup

The `-r` argument is resolved as follows:

1. If the argument contains `/` or ends with `.toml`, treat as a **file path**.
2. Otherwise, search for `<name>.toml` in the recipe search path:
   - `./.canister/`
   - `$XDG_CONFIG_HOME/canister/recipes/`
   - `/etc/canister/recipes/`
3. First match wins (project-local takes precedence over user-global).

```bash
can run -r elixir -- mix test              # name lookup → elixir.toml
can run -r recipes/custom.toml -- mix test # file path
can run -r ./my-policy.toml -- echo hi     # file path (contains /)
```

### Auto-Detection via match_prefix

Recipes can declare `match_prefix` patterns in their `[recipe]` metadata.
During CLI setup (before forking), the command binary path is resolved and
canonicalized. Each discovered recipe's `match_prefix` is checked against
the resolved path. Matching recipes are automatically merged into the chain
between `base.toml` and explicit `-r` args.

This replaces the previous hardcoded `detect_command_prefix()` logic.
Adding support for a new package manager is "write a `.toml` file" rather
than "modify Rust code".

### Environment Variable Expansion

Recipe paths support environment variable expansion:

| Syntax | Expansion |
|--------|-----------|
| `$HOME` | Value of `$HOME` |
| `$USER` | Value of `$USER` |
| `${XDG_CONFIG_HOME}` | Value of `$XDG_CONFIG_HOME` |
| `$$` | Literal `$` |

Expansion applies to `[filesystem].read`, `[filesystem].deny`,
`[process].exec`, and `[recipe].match_prefix`. It is performed
during config resolution (after merge, before the sandbox uses the paths).

```toml
[filesystem]
read = ["$HOME/.cargo", "$HOME/.rustup", "$HOME/project"]

[recipe]
match_prefix = ["$HOME/.cargo"]
```

---

## `[recipe]` (metadata)

Optional metadata section for recipe files. Not used for policy enforcement
but controls recipe discovery and composition behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `string` (optional) | — | Human-readable recipe name |
| `description` | `string` (optional) | — | Short description shown by `can recipe list` |
| `match_prefix` | `string[]` | `[]` | Path prefixes for auto-detection (env vars expanded) |

```toml
[recipe]
name = "nix"
description = "Nix package manager (/nix/store)"
match_prefix = ["/nix/store"]
```

---

## `[filesystem]`

Controls what the sandboxed process can see and access on the filesystem.

When filesystem isolation is active (requires a MAC policy on Ubuntu 24.04+ and
Fedora 41+), the sandbox starts with an empty tmpfs root. Only explicitly allowed
paths and essential system paths are bind-mounted read-only.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `read` | `string[]` | `[]` | Paths bind-mounted **read-only** into the sandbox |
| `write` | `string[]` | `[]` | Paths bind-mounted **writable** — changes persist on the host |
| `deny` | `string[]` | `[]` | Paths explicitly denied (checked **before** `read`/`write`) |

Note: read access still matters — a *readable* credential file is exactly
what the DLP layer exists to stop from leaving. `read` names the grant
honestly; `write` is the one that persists to the host.

**Behavior:**

- Deny rules take precedence over `read`/`write` rules.
- Paths are matched by prefix: allowing `/usr/lib` also allows `/usr/lib/python3`.
- Essential paths are defined in `recipes/base.toml` (embedded in the binary,
  overridable on disk) and always bind-mounted: `/bin`, `/sbin`, `/usr/bin`,
  `/usr/sbin`, `/lib`, `/lib64`, `/usr/lib`, `/etc`.
- **Auto-detection:** When the command binary lives outside standard FHS paths
  (e.g., installed via Nix, Homebrew, Cargo, etc.), Canister auto-detects the
  appropriate package manager recipe via `match_prefix` and merges it into the
  recipe chain, bringing the necessary mount paths automatically. See
  [Auto-Detection via match_prefix](#auto-detection-via-match_prefix).
- When filesystem isolation is blocked (MAC system blocks mounts), the
  sandbox aborts. Run `sudo can setup` to install the security policy
  (use `--force` to reinstall if the policy is outdated).

```toml
[filesystem]
read  = ["/usr/lib", "/usr/bin", "/home/user/data"]
write = ["/tmp/workspace"]
deny  = ["/etc/shadow", "/etc/passwd", "/root", "/home/user/.ssh"]
```

### Package Manager Support

When the command binary is installed outside standard system paths, Canister
uses recipe-based auto-detection to ensure the binary is visible inside the
sandbox. Each package manager has a recipe with `match_prefix` patterns:

| Recipe | Auto-detects when binary is under | Mounts |
|--------|----------------------------------|--------|
| `nix.toml` | `/nix/store` | `/nix/store` (read-only) |
| `homebrew.toml` | `/opt/homebrew`, `/home/linuxbrew/.linuxbrew` | The matching prefix |
| `cargo.toml` | `$HOME/.cargo`, `$HOME/.rustup` | `$HOME/.cargo`, `$HOME/.rustup` |
| `snap.toml` | `/snap` | `/snap` |
| `flatpak.toml` | `/var/lib/flatpak`, `$HOME/.local/share/flatpak` | The matching prefix |
| `gnu-store.toml` | `/gnu/store` | `/gnu/store` |

**How it works:**

1. The command path is **canonicalized** (all symlinks resolved) at startup.
2. Each discovered recipe's `match_prefix` is checked against the resolved path.
3. Matching recipes are merged into the composition chain, bringing their
   `[filesystem].read` paths, `[process].exec` entries, and any
   other policy fields.
4. For content-addressed stores like `/nix/store`, the entire tree is mounted.
   Binaries reference sibling store entries freely, making individual-entry
   mounting impractical.

**Security note:** Auto-detection makes the prefix *visible* inside the
sandbox but does not grant execution permission. The `[process] exec`
policy independently controls what binaries can be executed. Package
manager recipes that restrict exec use `exec = ["/nix/store/*", …]`
prefix rules to authorize execution within the mounted tree.

**Adding a new package manager:** Create a new `.toml` recipe with
appropriate `match_prefix`, `[filesystem].read`, and (if restricting
exec) `[process].exec` entries. No Rust code changes needed.

---

## `[network]`

Controls network access. Secure by default: all network access is denied unless
explicitly allowed.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `egress` | `"proxy" \| "none"` | `"proxy"` | Outbound networking mode. Unfiltered/direct egress is `[unsafe] unfiltered_egress` (it disables DLP + contract gates). |
| `contract_mode` | `"strict" \| "relaxed"` | `"strict"` | Default for hosts without a `[[host]]` block. `strict` refuses; `relaxed` allows + logs. |

IP-literal egress (`reachable_ips`) and port forwarding (`expose_ports`)
moved to [`[unsafe]`](#unsafe): both bypass the per-host contract and DLP
gates, so they are quarantined where the cost is visible.

FQDN egress goes through the top-level [`[[host]]`](#host) table, not
this section. Each `[[host]]` block names a domain and the request
shapes accepted on it; see that section for the full schema.

**Network mode determination:**

The effective egress mode determines isolation behavior:

| `egress` | Mode | Description |
|----------|------|-------------|
| `none` | **None** | No outbound network. Empty network namespace, loopback only. |
| `proxy` | **Filtered** | Outbound traffic must go through local proxy (kernel-enforced). |
| `[unsafe] unfiltered_egress = true` | **Full/Filtered** | Direct outbound — **DLP and contract gates do not run**. Filtered for policy checks when `reachable_ips`/`expose_ports` are set; otherwise full host network namespace. |

Specifying `[unsafe] expose_ports` automatically upgrades None mode to
Filtered mode (port forwarding requires a functional network namespace
with pasta).

**Domain matching:**

Domains are matched including subdomains. Allowing `pypi.org` also allows
`files.pythonhosted.org` if listed, but does **not** automatically allow
subdomains of `pypi.org`. Each domain must be listed explicitly.

**IP/CIDR matching** (via [`[unsafe] reachable_ips`](#unsafe)):

IPs support both exact match and CIDR notation:

```toml
[unsafe]
reachable_ips = [
    "93.184.216.34",        # exact IPv4
    "10.0.0.0/8",           # IPv4 CIDR
    "2606:2800:220:1::/64", # IPv6 CIDR
]
```

**Filtered mode requirements:**

Filtered mode requires `pasta` (from the passt project) installed on the host:

```bash
sudo apt install passt       # Debian/Ubuntu
sudo dnf install passt       # Fedora
```

In filtered mode, pasta mirrors the host's network configuration into the
sandbox namespace. pasta copies the host's real IP addresses and routes into
the namespace. DNS is handled via a link-local address:

| Address | Role |
|---------|------|
| Host's default gateway | Gateway |
| `169.254.0.1` | DNS server (link-local, pasta `--dns`) |
| Host's real IP | Sandbox IP (mirrored from host) |

```toml
[network]
egress = "proxy"
[[host]]
domain = "pypi.org"

[[host]]
domain = "files.pythonhosted.org"

[[host]]
domain = "registry.npmjs.org"
```

**Port forwarding (`ports`):**

Port forwarding uses Docker/Podman-compatible syntax and is specified via
the `-p` / `--port` CLI flag or the `ports` config field:

```bash
# CLI usage
can run -p 8080:80 -- my-server
can run -p 127.0.0.1:3000:3000 -p 5432:5432/tcp -- my-app
```

```toml
# Config usage (port forwarding is an isolation-weakening inbound exposure)
[unsafe]
expose_ports = ["8080:80", "127.0.0.1:3000:3000", "5353:53/udp"]
```

Syntax: `[ip:]hostPort:containerPort[/protocol]`

| Component | Required | Default | Description |
|-----------|----------|---------|-------------|
| `ip` | No | `0.0.0.0` | Host IP to bind (e.g., `127.0.0.1`) |
| `hostPort` | Yes | — | Port on the host |
| `containerPort` | Yes | — | Port inside the sandbox |
| `protocol` | No | `tcp` | `tcp` or `udp` |

---

## `[[host]]`

Per-destination egress contract. **One `[[host]]` block per FQDN you
allow the sandbox to reach.** The block answers every question about
that upstream in one place: connect permission, the request shapes
that are legitimate, and which DLP detectors may carry verdicts on
this host as `Warn` instead of `Block`.

There is no separate connect-permission list. Having a `[[host]]`
block at all is the permission to dial; the block's other fields
tighten what's allowed from there. The minimum block is one line
(`domain = "x"`) — equivalent to "allow this host, any shape."

```toml
# Minimum-viable allow.
[[host]]
domain = "static.example.com"

# Full picture for a service we care about.
[[host]]
domain             = "api.github.com"
methods            = ["GET", "POST", "PATCH", "PUT", "DELETE"]
content_types      = ["application/json", "application/vnd.github+json"]
paths              = ["/repos/", "/user/", "/orgs/"]
max_request_bytes  = 1_048_576                       # 1 MiB
allow_credentials  = ["github_pat"]                  # downgrade github_pat hits to Warn here

# Per-host escape hatch.
[[host]]
domain        = "weird-tool.corp.internal"
contract_mode = "relaxed"

# Route a destination to a service on the host's loopback (ADR-0013).
# The workload still calls https://claims.mock.internal/... — the proxy
# terminates TLS, applies this contract, then forwards to 127.0.0.1:4101
# over plain HTTP. Requires [network] allow_host_loopback = true.
[[host]]
domain   = "claims.mock.internal"
upstream = "loopback:4101"
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `domain` | `string` | **required** | FQDN this block applies to. Wildcards (`*.github.com`) match one or more subdomain levels; bare domains match exact + any subdomain. Most-specific match wins. |
| `methods` | `string[]` | `[]` | Allowed HTTP methods (case-insensitive). Empty = any. |
| `content_types` | `string[]` | `[]` | Allowed request `Content-Type` values (matched on `mime/subtype` portion; `; charset=...` parameters are ignored). Empty = any. |
| `paths` | `string[]` | `[]` | Path prefixes the request URI must start with. Empty = any. |
| `max_request_bytes` | `u64` | unset | Per-host request body cap. Applies after the global `max_streamed_body_bytes`. |
| `allow_credentials` | `string[]` | `[]` | DLP detector ids whose verdicts on this host downgrade from `Block` to `Warn` (e.g. `["github_pat"]` means the worker may legitimately carry a github PAT in `Authorization` to this host). |
| `contract_mode` | `"strict" \| "relaxed"` | inherit `[network] contract_mode` | Per-host override of the global default. Only affects the unknown-host decision once you're inside this block; field-level checks still run. |
| `upstream` | `string` | unset | Dial this host on the *host's* loopback instead of the real destination: `"loopback:<port>"`. TLS is terminated by the proxy as usual and the loopback hop is plain HTTP; the `Host` header keeps the original name. Requires `[network] allow_host_loopback = true`; a malformed value or a missing `allow_host_loopback` is refused at startup. See [ADR-0013](adr/0013-loopback-upstream-routing.md). |

Multiple `[[host]]` entries with the same `domain` merge by:
**union** on vec fields, **max** for `max_request_bytes`, **last-Some-wins**
for `contract_mode` and `upstream`. A project recipe can extend (never silently
restrict) a canister-shipped contract by writing another `[[host]]`
with the same domain.

### Refusal behaviour

If a request reaches the proxy with a destination that has no matching
`[[host]]` block, the gate decides based on `[network] contract_mode`:

- **`strict`** (default) — refuse with **415** (or **413** for body-size),
  `x-canister-error: contract-refused`, and a response body that
  carries the **exact `[[host]]` patch** to paste into `canister.toml`
  to allow this exact shape.
- **`relaxed`** — allow the request but emit an `unknown_host_contract`
  tracing event. Intended for prototyping where the upstream set
  isn't known up front.

See [`docs/refusals.md`](refusals.md) for the operator-facing
walkthrough (415 vs 451, how to read the patch, escape hatches).

### Shipped service contracts

Canister ships contracts for the upstreams workers most commonly hit
under `recipes/services/`: `github.toml`, `openai.toml`,
`anthropic.toml`, `npm.toml`, `pypi.toml`, `huggingface.toml`,
`docker.toml`, `aws.toml`, `stripe.toml`, `slack.toml`. Compose
them with `-r service:github` (etc.) or via a project manifest.

---

## `[network.dlp]`

Data Loss Prevention layer running inside the L7 egress proxy. Scans
outbound HTTP traffic for credential patterns (GitHub PATs, npm tokens,
AWS keys, Slack tokens, SSH private keys, generic bearer tokens) and
enforces per-host credential scoping via the `allow_credentials` field
on each [`[[host]]`](#host) block — a GitHub PAT bound for
`registry.npmjs.org` will be blocked even though both hosts are
reachable. See [DLP](DLP.md) for the full threat model and detector
list.

DLP only runs when traffic is inspectable, i.e. when
`network.egress = "proxy"`.

```toml
[network.dlp]
enabled = true
canary_tokens = true              # default when DLP is enabled
max_decode_depth = 32             # base64/hex/percent recursion cap
decompress = true                 # gzip/deflate/brotli before scan
dns_entropy_threshold = 4.5       # Shannon entropy per DNS label
session_entropy_budget = 8192     # cumulative high-entropy bytes/session

# Env-var secrets to fake-and-swap: the sandbox runs with a fake value,
# the proxy substitutes the real one only on egress to a host authorised
# for that credential. See DLP.md § Fake-Secret Swap.
fake_secrets = [
  { env = "GITHUB_TOKEN", credential = "github_pat" },
]

# Extend credential scope by adding allow_credentials on the host:
[[host]]
domain            = "github.corp.example.com"
methods           = ["GET", "POST", "PATCH", "PUT", "DELETE"]
content_types     = ["application/json"]
allow_credentials = ["github_pat"]
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | `bool` | `false` | Enable DLP scanning. Implicitly `true` under `--strict` when `egress = "proxy"`. |
| `canary_tokens` | `bool` | `true` when DLP enabled | Inject fake credentials into the sandbox env and treat any outbound appearance as exfiltration. |
| `max_decode_depth` | `usize` | `32` | Encoding chain recursion depth (base64 / hex / percent). |
| `decompress` | `bool` | `true` | Inflate gzip / deflate / brotli bodies before scanning. |
| `dns_entropy_threshold` | `f64` | `4.5` | Shannon entropy per DNS label above which the hostname is blocked. |
| `session_entropy_budget` | `u64` | `8192` | Cumulative high-entropy bytes allowed across one sandbox session before further requests are blocked. |
| `external_canaries` | `{ value, data_class, allowed_hosts }[]` | `[]` | Values planted in the workload's *input data* by an orchestrator, each tagged with the class of data it stands for and the destinations allowed to see it. Recognised on egress like generated canaries, but a hit on an allowed host is recorded (`canary_fire` with `allowed: true`) instead of blocked; any other host is a leak. Never injected into the sandbox environment. Also settable per run with `--canaries-file`. See [ADR-0012](adr/0012-external-tagged-canaries.md). |
| `fake_secrets` | `{ env, credential }[]` | `[]` | Env-var secrets the sandbox never sees in cleartext: it receives a fake matching `credential`'s pattern, and the proxy swaps in the real host value only on egress to a host authorised for that credential. `credential` must be a detector with a generatable pattern (`github_pat`, `npm_token`, `openai_key`, `anthropic_key`, `slack_token`, `stripe_key`). Dropped for untrusted recipes, like `allow_credentials`. See [DLP](DLP.md#fake-secret-swap). |

```toml
# Watch for a planted AHV number and record where it goes.
[[network.dlp.external_canaries]]
value         = "CNRY-7Q2X-AHV"
data_class    = "ahv"
allowed_hosts = ["claims.mock.internal", "api.anthropic.com"]
```

Credential-flow scope is configured per host via the
`allow_credentials` field on [`[[host]]`](#host).

### Built-in scopes

Each detector has a baseline list of *home domains* hardcoded in the
detector registry — destinations where it's universally legitimate
for that credential type to flow:

| Detector | Built-in home domains |
|---|---|
| `github_pat` | `github.com`, `*.github.com` |
| `npm_token` | `registry.npmjs.org` |
| `aws_access_key` | `*.amazonaws.com` |
| `slack_token` | `*.slack.com` |
| `bearer_token` | *(none — requires explicit `allow_credentials = ["bearer_token"]` on the host)* |
| `ssh_private_key`, `canary_token` | *(none — always block)* |
| `generic_high_entropy` | *(warn only, block in `--strict`)* |

Add to this set per-host via `allow_credentials` on the relevant
`[[host]]` block. Built-in lists are never narrowed.

### Merge semantics

| Field | Merge rule |
|---|---|
| `enabled` | OR — any `Some(true)` wins (security escalation, never reversed) |
| `canary_tokens` | OR |
| `max_decode_depth`, `decompress`, `dns_entropy_threshold`, `session_entropy_budget` | last-Some-wins |

A downstream recipe can never disable DLP that an upstream recipe
enabled.

### Interaction with `--strict` / `--monitor`

- `--strict` implicitly enables DLP (when `egress = "proxy"`) and
  promotes `generic_high_entropy` from `warn` to `block`.
- `--monitor` logs DLP findings at `warn!` level but forwards the
  request, adding an `x-canister-dlp-warning` header so the sandboxed
  process can observe what would have been blocked.

On block, the proxy returns `451 Unavailable For Legal Reasons` with
headers `x-canister-error: dlp-blocked` and
`x-canister-dlp-detector: <name>`.

---

## `[process]`

Controls process creation, environment filtering, and executable restrictions.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_pids` | `int` (optional) | none | Maximum number of processes (via `RLIMIT_NPROC`) |
| `exec` | `"any" \| "entrypoint-only" \| string[]` | `"any"` | Which binaries may be exec'd. An explicit list is an allow-list (entries ending `/*` are prefix rules). |
| `env_passthrough` | `string[]` | `[]` | Environment variables to pass from host (all others stripped) |

**PID namespace isolation:**

Every sandboxed process runs in its own PID namespace. The sandboxed command
becomes PID 1 and cannot see or signal any host processes.

**Environment filtering:**

When `env_passthrough` is empty, the sandbox starts with a completely clean
environment — zero host environment variables are inherited. This is the most
secure default.

When `env_passthrough` contains variable names, only those variables are kept.
A minimal `PATH=/usr/local/bin:/usr/bin:/bin` is injected if `PATH` is not
in the passthrough list.

**`max_pids` enforcement:**

Uses `RLIMIT_NPROC` to cap the number of processes. When exceeded, `fork()`
returns `EAGAIN`. This is a per-UID limit, which is effective inside the
sandbox's user namespace (where the process runs as UID 0 mapped to the host
user).

**`exec` validation:**

`exec = "any"` (the default) places no restriction. `exec = "entrypoint-only"`
permits only the sandbox entrypoint command (child execs denied once the
USER_NOTIF supervisor enforces it). An explicit list is an allow-list: the
resolved command path must match a listed path, else execution is rejected
before forking. (Replaces the old `allow_execve = []`-means-"any" footgun —
an empty intent is now stated, not implied.)

**Prefix rules:** Entries ending in `/*` match any binary under that
directory tree. For example, `/nix/store/*` allows any binary whose resolved
path starts with `/nix/store/`. The match requires a `/` boundary — 
`/nix/store-extra/foo` does NOT match `/nix/store/*`. This is essential for
content-addressed stores like Nix where binary paths contain unpredictable
hashes.

**Ongoing enforcement:** When the USER_NOTIF supervisor is active (kernel
5.9+, default), every `execve()` and `execveat()` call inside the sandbox is
intercepted and validated against the `exec` allow-list. This means child
processes cannot exec arbitrary binaries. When the notifier is disabled
(kernel < 5.9 or `notifier = false`), only the initial command is validated,
and child processes can exec any binary visible in the mount namespace.

```toml
[process]
max_pids = 64
exec = ["/usr/bin/python3", "/usr/bin/pip", "/nix/store/*"]
env_passthrough = ["PATH", "HOME", "LANG", "TERM", "VIRTUAL_ENV"]
```

---

## `[resources]`

Resource limits enforced via cgroups v2. Requires systemd with per-user
cgroup delegation (default on most modern distributions).

**Opt-in:** Resource limits are not included in any of the shipped base
recipes. They are entirely opt-in — add `memory_mb` and/or `cpu_percent`
to your own recipe when needed.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `memory_mb` | `int` (optional) | none | Memory limit in megabytes |
| `cpu_percent` | `int` (optional) | none | CPU limit as percentage of one core (e.g., 50 = 50%) |

**How it works:**

Canister detects the current cgroup from `/proc/self/cgroup`, creates a
child cgroup (`canister-<pid>`), writes `memory.max` and `cpu.max`, and
moves the sandboxed process into it. No root required.

- `memory_mb = 512` → `memory.max = 536870912` (512 MiB). Exceeding the
  limit triggers the kernel OOM killer.
- `cpu_percent = 50` → `cpu.max = "50000 100000"` (50ms quota per 100ms
  period), capping the process to 50% of one CPU core.

**Failure behavior:** If cgroup setup fails (e.g., no cgroup v2, no
delegation), the sandbox aborts. In strict mode (`--strict`), seccomp
uses KILL_PROCESS for immediate termination on any denied syscall.

```toml
[resources]
memory_mb = 512
cpu_percent = 100
```

---

## `[syscalls]`

Customizes the seccomp BPF baseline and enforcement mode.

Canister ships a single default seccomp baseline defined in
`recipes/default.toml` (~187 allowed syscalls, ~18 always-denied). The
baseline is embedded in the binary at compile time and can be overridden by
placing a `default.toml` in the recipe search path (`./.canister/`,
`$XDG_CONFIG_HOME/canister/recipes/`, `/etc/canister/recipes/`).

Regular recipes customize the baseline by adding or removing syscalls with
`allow_extra` / `deny_extra`. The baseline itself uses `allow` / `deny`
(absolute lists). These two pairs are **mutually exclusive** — a recipe
either IS the baseline (uses `allow`/`deny`) or EXTENDS it (uses
`allow_extra`/`deny_extra`).

### Override fields (for regular recipes)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_extra` | `string[]` | `[]` | Syscalls to add to the baseline allow list. **Dangerous syscalls** (`ptrace`, `bpf`, `mount`, `io_uring_*`, `personality`, `seccomp`, …) are rejected here — they must go in [`[unsafe] extra_syscalls`](#unsafe). |
| `deny_extra` | `string[]` | `[]` | Syscalls to add to the deny list (also removed from allow list) |
| `notifier` | `bool` (optional) | auto-detect | Enable/disable the USER_NOTIF supervisor for argument-level syscall filtering |

Seccomp is **always default-deny (allow-list)**. Flipping to default-allow
(deny-list) inverts the security posture, so it is `[unsafe] seccomp_default_allow`
rather than a `[syscalls]` field.

### Absolute fields (for `default.toml` only)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow` | `string[]` | `[]` | Complete allow list (replaces the baseline, not additive) |
| `deny` | `string[]` | `[]` | Complete deny list (replaces the baseline, not additive) |

**Mutual exclusion:** Using `allow` or `deny` together with `allow_extra`
or `deny_extra` in the same `[syscalls]` section is a validation error.

**Seccomp modes:**

| Mode | Default action | Listed syscalls | How to select |
|------|---------------|-----------------|----------|
| allow-list | DENY all | Only baseline + `allow_extra` permitted | Default (recommended) |
| deny-list | ALLOW all | Only baseline deny + `deny_extra` blocked | `[unsafe] seccomp_default_allow = true` |

**Examples:**

```toml
# Add a benign syscall to the baseline allow list.
[syscalls]
allow_extra = ["statx"]

# Block personality for extra hardening (deny is always fine).
[syscalls]
deny_extra = ["personality"]

# Dangerous syscalls (ptrace, io_uring, …) are isolation-weakening and
# must be declared explicitly in [unsafe]:
[unsafe]
extra_syscalls = ["ptrace", "io_uring_setup", "io_uring_enter", "io_uring_register"]

# Default-allow seccomp (inverts the posture) is also an [unsafe] knob:
[unsafe]
seccomp_default_allow = true
```

See [SECCOMP.md](SECCOMP.md) for details on the baseline syscall set and
how the embed+override resolution works.

### USER_NOTIF supervisor (`notifier`)

The `notifier` field controls the `SECCOMP_RET_USER_NOTIF` supervisor, which
provides argument-level filtering for `connect()`, `clone()`/`clone3()`,
`socket()`, `execve()`, and `execveat()`.

| Value | Behavior |
|-------|----------|
| `true` | Force the notifier on (fails if kernel < 5.9) |
| `false` | Force the notifier off |
| omitted | Auto-detect: enabled if kernel >= 5.9 and not in monitor mode |

When the notifier is active, `connect()` calls are filtered against the
resolved IPs from each `[[host]].domain` and `[unsafe] reachable_ips`,
`clone()`/`clone3()` are blocked from creating new namespaces, `socket()` is
blocked from creating `AF_NETLINK` or `SOCK_RAW` sockets, and
`execve()`/`execveat()` are validated against the `[process] exec` allow-list
for every execution (not just the initial command).

The notifier is merged using the **last-Some-wins** strategy during recipe
composition, consistent with other `Option<bool>` scalar fields.

```toml
# Disable the notifier for compatibility with older kernels
[syscalls]
notifier = false

# Force it on (fail loudly if not supported)
[syscalls]
notifier = true
```

See [SECCOMP.md](SECCOMP.md#user_notif-supervisor) for the full technical
description.

---

## `[unsafe]`

Every setting that **lowers isolation below the baseline** lives here, and
**nowhere else** — these fields are rejected in their old sections. The
payoff: a recipe with no `[unsafe]` block is provably unable to weaken the
sandbox, `grep -rL '\[unsafe\]' recipes/` is the audited-safe set, and `can`
prints a one-line `⚠ unsafe` summary at runtime when any are active.

| Field | Type | Default | Lowers isolation by… |
|-------|------|---------|----------------------|
| `unfiltered_egress` | `bool` | `false` | bypassing the proxy → **DLP and contract gates do not run** (was `egress = "direct"`) |
| `reachable_ips` | `string[]` | `[]` | allowing IP-literal egress with no service identity — bypasses contract + DLP gates (was `[network] allow_ips`) |
| `host_loopback` | `bool` | `false` | letting the sandbox reach host `127.0.0.1` services via `host.canister.local` (was `[network] allow_host_loopback`) |
| `expose_ports` | `string[]` | `[]` | forwarding host ports into the sandbox — inbound exposure (was `[network] ports`) |
| `seccomp_default_allow` | `bool` | `false` | flipping seccomp to default-**allow** (deny-list) — the inverse of the secure default (was `[syscalls] seccomp_mode = "deny-list"`) |
| `extra_syscalls` | `string[]` | `[]` | adding high-risk syscalls (`ptrace`, `bpf`, `mount`, `io_uring_*`, …) rejected from `[syscalls] allow_extra` |

**Trust:** like `[[host]] allow_credentials`, `[unsafe]` is dropped from
*untrusted* (unpinned) recipes. Author project-specific weakenings in your
`canister.toml` (`[sandbox.<name>.unsafe]`), which is trusted.

**Validation:** declaring `unfiltered_egress` alongside DLP / `fake_secrets`
/ `allow_credentials` is a parse error — those do nothing without the proxy.

```toml
[unsafe]
unfiltered_egress = true              # direct egress — DLP & contracts OFF
reachable_ips     = ["10.0.0.5/32"]
host_loopback     = true
expose_ports      = ["8080:80"]
seccomp_default_allow = true
extra_syscalls    = ["ptrace"]
```

---

## `[proxy]`

L7 proxy settings used by proxy egress mode.

```toml
[proxy]
max_buffered_body_bytes = 8388608   # 8 MiB (default)
upstream_request_timeout_ms = 30000  # 30 s (default)
```

### Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `max_buffered_body_bytes` | `usize` | `8388608` | Max bytes buffered for DLP body scanning |
| `upstream_request_timeout_ms` | `u64` | `30000` | Upstream request timeout in milliseconds |

### Enforcement semantics

When `network.egress = "proxy"`:

- sandboxed processes may only open outbound INET/INET6 connections to:
  - loopback proxy endpoint (`127.0.0.1:<proxy_port>` / `::1:<proxy_port>`)
  - configured DNS server on port 53
- direct outbound internet access is denied by seccomp USER_NOTIF policy
  even if `HTTP_PROXY`/`HTTPS_PROXY` env vars are unset.

This makes seccomp-notify the first-line defense and proxy the forwarding path
for legitimate traffic.

---

## Strict Mode

Strict mode (`--strict` or `strict = true` in config) tightens all enforcement
for CI and production use.

**Config:**

```toml
strict = true
```

**CLI:**

```bash
can run --strict --recipe policy.toml -- python3 script.py
```

The CLI `--strict` flag can only tighten — if the config sets `strict = true`,
the CLI cannot override it to false.

**Changes in strict mode:**

| Enforcement point | Normal mode | Strict mode |
|-------------------|-------------|-------------|
| Filesystem isolation | **Aborts** on failure | **Aborts** on failure |
| Network setup | **Aborts** on failure | **Aborts** on failure |
| Loopback bring-up | **Aborts** on failure | **Aborts** on failure |
| Seccomp deny action | `EPERM` (process survives) | `KILL_PROCESS` (immediate termination) |
| Cgroup setup | **Aborts** on failure | **Aborts** on failure |

The key difference is the seccomp deny action: normal mode returns EPERM
so the process can handle denials gracefully; strict mode kills the process
immediately on any denied syscall.

**Mutual exclusion:** `--strict` and `--monitor` cannot be used together.
Strict mode ensures full enforcement; monitor mode relaxes it. These are
contradictory intents.

---

## Monitor Mode

Monitor mode (`--monitor`) is a CLI flag, not a config field. It relaxes
enforcement across all policy sections so you can observe what would be
blocked without actually blocking it.

```bash
can run --monitor --recipe my_policy.toml -- python3 script.py
```

**What changes in monitor mode:**

| Section | Normal | Monitor |
|---------|--------|---------|
| `[process].exec` | Blocks unlisted commands | Logs warning, allows |
| `[process].env_passthrough` | Strips unlisted vars | Logs stripped count, passes all |
| `[process].max_pids` | Enforces RLIMIT_NPROC | Logs limit, skips enforcement |
| `[syscalls]` seccomp | Returns EPERM on denied syscalls | Logs to kernel audit, allows |
| `[filesystem]` | Overlay + pivot_root | Unchanged (isolation active) |
| `[network]` | Namespace + pasta | Unchanged (isolation active) |

**Reading monitor output:**

- Look for `MONITOR:` prefixed log lines in stderr.
- Seccomp events appear in kernel logs: `journalctl -k | grep seccomp`.
- A pre-run policy preview and post-run summary are printed automatically.

Monitor mode is a development tool. It provides **no security guarantees**.
Cannot be combined with `--strict`.

---

## Inspecting the Resolved Policy

Use `can recipe show` to see the fully resolved policy after all recipe
merging and environment variable expansion:

```bash
# Show the base policy (no recipes)
can recipe show

# Show the resolved policy with a recipe
can recipe show -r elixir

# Show with auto-detection (pass the command to trigger match_prefix)
can recipe show -r elixir -- mix test

# Compose multiple recipes and see the result
can recipe show -r nix -r elixir

# Save to a standalone recipe file
can recipe show -r nix -r elixir > my-custom.toml
can run -r my-custom.toml -- mix test
```

The output is valid TOML and includes all resolved fields:

```toml
strict = false

[filesystem]
read = ["/bin", "/sbin", "/usr/bin", ...]
deny = ["/etc/shadow", "/etc/gshadow"]

[network]
[[host]]
domain = "hex.pm"

[[host]]
domain = "repo.hex.pm"

[[host]]
domain = "builds.hex.pm"
egress = "proxy"

[process]
exec = ["/nix/store/*"]
env_passthrough = ["PATH", "HOME", ...]

[resources]

[syscalls]
allow_extra = ["statx"]
```

This serves two purposes:

1. **Auditing** — see exactly what policy will be enforced before running.
2. **Standalone recipes** — capture the output and use it as a custom
   recipe that doesn't depend on any other recipe files.

---

## Examples

### Minimal: deny everything

No config file needed. This is the default.

```bash
can run -- echo "hello"
```

Equivalent to:

```toml
[filesystem]
[network]
egress = "none"
[syscalls]
```

### Python data science

Allow pip installs from PyPI and access to a workspace directory.

```toml
[filesystem]
read = [
    "/usr/lib",
    "/usr/bin",
    "/usr/local/lib",
    "/tmp/workspace",
]
deny = ["/etc/shadow", "/root"]

[network]
egress = "proxy"
[[host]]
domain = "pypi.org"

[[host]]
domain = "files.pythonhosted.org"
[process]
env_passthrough = ["PATH", "HOME", "LANG", "VIRTUAL_ENV"]
```

### Node.js build

Allow npm registry access and a project directory.

```toml
[filesystem]
read = [
    "/usr/lib",
    "/usr/bin",
    "/usr/local",
    "/home/user/project",
]

[network]
egress = "proxy"
[[host]]
domain = "registry.npmjs.org"

[[host]]
domain = "nodejs.org"
[process]
env_passthrough = ["PATH", "HOME", "NODE_ENV"]
```

### Full network trust

For trusted code that needs unrestricted network access but should still be
filesystem- and syscall-restricted.

```toml
[filesystem]
read = ["/tmp/workspace"]

[network]
egress = "direct"
```

### Air-gapped

No network, no filesystem beyond essentials, strict seccomp.

```toml
[filesystem]
read = ["/tmp/workspace"]
deny  = ["/etc", "/root", "/home"]

[network]
egress = "none"
```

### Strict CI

All-or-nothing enforcement. If any isolation layer can't be set up, the
sandbox refuses to start. Denied syscalls kill the process immediately.

```toml
strict = true

[filesystem]
read = ["/tmp/workspace"]

[network]
egress = "none"

[process]
max_pids = 64
exec = ["/usr/bin/python3"]

[resources]
memory_mb = 512
cpu_percent = 100

[syscalls]
```

### Elixir/Erlang (mix tasks, iex, Phoenix)

Run mix tasks, iex shells, or Phoenix servers with hex.pm access.
Use with `-r nix` or `-r homebrew` if Elixir is installed via a package manager.

```toml
[recipe]
name = "elixir"
description = "Elixir/Erlang (BEAM VM) — mix, iex, Phoenix"

[filesystem]
read = [
    "/usr/lib",
    "/usr/bin",
    "/usr/local/lib",
    "/usr/local/bin",
    "/lib",
    "/tmp/workspace",
]
deny = ["/etc/shadow", "/root"]

[network]
[[host]]
domain = "hex.pm"

[[host]]
domain = "repo.hex.pm"

[[host]]
domain = "builds.hex.pm"
egress = "proxy"

[process]
max_pids = 256
env_passthrough = [
    "PATH", "HOME", "LANG", "TERM",
    "MIX_ENV", "MIX_HOME", "HEX_HOME",
    "ERL_AFLAGS", "ELIXIR_ERL_OPTIONS",
    "SECRET_KEY_BASE", "DATABASE_URL", "PORT",
]

[syscalls]
allow_extra = ["statx"]   # BEAM tracing tools (:observer, :dbg, recon)
```

Usage with composition:

```bash
# Nix-installed Elixir: nix.toml auto-detected, elixir.toml explicit
can run -r elixir -- mix test

# Explicit composition
can run -r nix -r elixir -- mix test

# Strict CI
can run --strict -r elixir -- mix test
```
