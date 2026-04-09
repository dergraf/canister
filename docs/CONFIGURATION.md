# Configuration Reference

Canister uses TOML configuration files with strict schema validation. Unknown
fields are rejected at parse time.

When no config file is provided (`can run -- command`), a **default deny-all**
policy is used: no filesystem access, no network, default seccomp baseline.

## Table of Contents

- [Recipe Composition](#recipe-composition)
  - [Merge Semantics](#merge-semantics)
  - [Name-Based Lookup](#name-based-lookup)
  - [Auto-Detection via match_prefix](#auto-detection-via-match_prefix)
  - [Environment Variable Expansion](#environment-variable-expansion)
- [recipe (metadata)](#recipe-metadata)
- [filesystem](#filesystem)
- [network](#network)
- [process](#process)
- [resources](#resources)
- [syscalls](#syscalls)
- [Strict Mode](#strict-mode)
- [Allow Degraded Mode](#allow-degraded-mode)
- [Monitor Mode](#monitor-mode)
- [Inspecting the Resolved Policy](#inspecting-the-resolved-policy)
- [Examples](#examples)

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
| `deny_all` (`Option<bool>`) | **Last-Some-wins** — `None` preserves earlier value | Recipe A: `deny_all = true`, Recipe B: `deny_all = false` → `false` |
| `seccomp_mode` (`Option<SeccompMode>`) | **Last-Some-wins** | Same as `deny_all` |
| Numeric (`max_pids`, `memory_mb`, `cpu_percent`) | **Last-Some-wins** | Recipe A: `max_pids = 64`, Recipe B: `max_pids = 128` → `128` |
| `RecipeMeta` | **Overlay** — later recipe's metadata wins if present | — |

The "last-Some-wins" strategy means `None` (field not specified) preserves
the value from an earlier recipe, while `Some(value)` overwrites it.

### Name-Based Lookup

The `-r` argument is resolved as follows:

1. If the argument contains `/` or ends with `.toml`, treat as a **file path**.
2. Otherwise, search for `<name>.toml` in the recipe search path:
   - `./recipes/`
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

Expansion applies to `[filesystem].allow`, `[filesystem].deny`,
`[process].allow_execve`, and `[recipe].match_prefix`. It is performed
during config resolution (after merge, before the sandbox uses the paths).

```toml
[filesystem]
allow = ["$HOME/.cargo", "$HOME/.rustup", "$HOME/project"]

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

When filesystem isolation is active (requires AppArmor override on Ubuntu
24.04+), the sandbox starts with an empty tmpfs root. Only explicitly allowed
paths and essential system paths are bind-mounted read-only.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow` | `string[]` | `[]` | Paths to bind-mount read-only into the sandbox |
| `deny` | `string[]` | `[]` | Paths explicitly denied (checked **before** allow) |

**Behavior:**

- Deny rules take precedence over allow rules.
- Paths are matched by prefix: allowing `/usr/lib` also allows `/usr/lib/python3`.
- Essential paths are defined in `recipes/base.toml` (embedded in the binary,
  overridable on disk) and always bind-mounted: `/bin`, `/sbin`, `/usr/bin`,
  `/usr/sbin`, `/lib`, `/lib64`, `/usr/lib`, `/etc`.
- **Auto-detection:** When the command binary lives outside standard FHS paths
  (e.g., installed via Nix, Homebrew, Cargo, etc.), Canister auto-detects the
  appropriate package manager recipe via `match_prefix` and merges it into the
  recipe chain, bringing the necessary mount paths automatically. See
  [Auto-Detection via match_prefix](#auto-detection-via-match_prefix).
- When filesystem isolation is degraded (AppArmor blocks mounts), these
  settings have no effect -- the process sees the full host filesystem.

```toml
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/tmp/workspace", "/home/user/data"]
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
   `[filesystem].allow` paths, `[process].allow_execve` entries, and any
   other policy fields.
4. For content-addressed stores like `/nix/store`, the entire tree is mounted.
   Binaries reference sibling store entries freely, making individual-entry
   mounting impractical.

**Security note:** Auto-detection makes the prefix *visible* inside the
sandbox but does not grant execution permission. The `[process] allow_execve`
whitelist independently controls what binaries can be executed. Package
manager recipes include `allow_execve` prefix rules (e.g., `/nix/store/*`)
to authorize execution within the mounted tree.

**Adding a new package manager:** Create a new `.toml` recipe with
appropriate `match_prefix`, `[filesystem].allow`, and
`[process].allow_execve` entries. No Rust code changes needed.

---

## `[network]`

Controls network access. Secure by default: all network access is denied unless
explicitly allowed.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow_domains` | `string[]` | `[]` | Whitelisted domain names |
| `allow_ips` | `string[]` | `[]` | Whitelisted IPs or CIDR ranges (IPv4 and IPv6) |
| `deny_all` | `bool` | `true` | Deny all network except explicitly allowed |

**Network mode determination:**

The combination of fields determines which isolation mode is used:

| `deny_all` | Allowlists | Mode | Description |
|------------|------------|------|-------------|
| `true` | empty | **None** | No network. Empty network namespace, loopback only. |
| `true` | non-empty | **Filtered** | Connectivity via slirp4netns. Domains pre-resolved. |
| `false` | any | **Full** | No isolation. Shares host network namespace. |

**Domain matching:**

Domains are matched including subdomains. Allowing `pypi.org` also allows
`files.pythonhosted.org` if listed, but does **not** automatically allow
subdomains of `pypi.org`. Each domain must be listed explicitly.

**IP/CIDR matching:**

IPs support both exact match and CIDR notation:

```toml
[network]
allow_ips = [
    "93.184.216.34",        # exact IPv4
    "10.0.0.0/8",           # IPv4 CIDR
    "2606:2800:220:1::/64", # IPv6 CIDR
]
```

**Filtered mode requirements:**

Filtered mode requires `slirp4netns` installed on the host:

```bash
sudo apt install slirp4netns   # Debian/Ubuntu
sudo dnf install slirp4netns   # Fedora
```

In filtered mode, the sandbox gets a virtual network interface via slirp4netns:

| Address | Role |
|---------|------|
| `10.0.2.2` | Gateway (host) |
| `10.0.2.3` | DNS server |
| `10.0.2.100` | Sandbox IP |

```toml
[network]
allow_domains = ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"]
deny_all = true
```

---

## `[process]`

Controls process creation, environment filtering, and executable restrictions.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_pids` | `int` (optional) | none | Maximum number of processes (via `RLIMIT_NPROC`) |
| `allow_execve` | `string[]` | `[]` | Executables the sandbox may exec (empty = allow all) |
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

**`allow_execve` validation:**

When non-empty, the resolved command path must match one of the listed paths.
If the command is not whitelisted, execution is rejected before forking.

**Prefix rules:** Entries ending in `/*` match any binary under that
directory tree. For example, `/nix/store/*` allows any binary whose resolved
path starts with `/nix/store/`. The match requires a `/` boundary — 
`/nix/store-extra/foo` does NOT match `/nix/store/*`. This is essential for
content-addressed stores like Nix where binary paths contain unpredictable
hashes.

**Ongoing enforcement:** When the USER_NOTIF supervisor is active (kernel
5.9+, default), every `execve()` and `execveat()` call inside the sandbox is
intercepted and validated against `allow_execve`. This means child processes
cannot exec arbitrary binaries. When the notifier is disabled (kernel < 5.9
or `notifier = false`), only the initial command is validated, and child
processes can exec any binary visible in the mount namespace.

```toml
[process]
max_pids = 64
allow_execve = ["/usr/bin/python3", "/usr/bin/pip", "/nix/store/*"]
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
delegation), the sandbox aborts by default. Pass `--allow-degraded` to
skip cgroup setup with a warning. In strict mode (`--strict`), cgroup
failure always aborts.

```toml
[resources]
memory_mb = 512
cpu_percent = 100
```

---

## `[syscalls]`

Customizes the seccomp BPF baseline and enforcement mode.

Canister ships a single default seccomp baseline defined in
`recipes/default.toml` (~170 allowed syscalls, ~16 always-denied). The
baseline is embedded in the binary at compile time and can be overridden by
placing a `default.toml` in the recipe search path (`./recipes/`,
`$XDG_CONFIG_HOME/canister/recipes/`, `/etc/canister/recipes/`).

Regular recipes customize the baseline by adding or removing syscalls with
`allow_extra` / `deny_extra`. The baseline itself uses `allow` / `deny`
(absolute lists). These two pairs are **mutually exclusive** — a recipe
either IS the baseline (uses `allow`/`deny`) or EXTENDS it (uses
`allow_extra`/`deny_extra`).

### Override fields (for regular recipes)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `seccomp_mode` | `string` | `"allow-list"` | Seccomp mode: `"allow-list"` (default deny) or `"deny-list"` (default allow) |
| `allow_extra` | `string[]` | `[]` | Syscalls to add to the baseline allow list |
| `deny_extra` | `string[]` | `[]` | Syscalls to add to the deny list (also removed from allow list) |
| `notifier` | `bool` (optional) | auto-detect | Enable/disable the USER_NOTIF supervisor for argument-level syscall filtering |

### Absolute fields (for `default.toml` only)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allow` | `string[]` | `[]` | Complete allow list (replaces the baseline, not additive) |
| `deny` | `string[]` | `[]` | Complete deny list (replaces the baseline, not additive) |

**Mutual exclusion:** Using `allow` or `deny` together with `allow_extra`
or `deny_extra` in the same `[syscalls]` section is a validation error.

**Seccomp modes:**

| Mode | Default action | Listed syscalls | Use case |
|------|---------------|-----------------|----------|
| `allow-list` | DENY all | Only baseline + `allow_extra` syscalls permitted | Production, CI (recommended) |
| `deny-list` | ALLOW all | Only baseline deny + `deny_extra` syscalls blocked | Compatibility, unknown workloads |

**Examples:**

```toml
# Elixir/BEAM: needs ptrace for observer/dbg/recon
[syscalls]
allow_extra = ["ptrace"]

# Strict: also block personality for extra hardening
[syscalls]
deny_extra = ["personality"]

# Full override: add io_uring support
[syscalls]
allow_extra = ["ptrace", "personality", "seccomp", "io_uring_setup", "io_uring_enter", "io_uring_register"]

# Deny-list mode for maximum compatibility
[syscalls]
seccomp_mode = "deny-list"
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
resolved IPs from `allow_domains` and `allow_ips`, `clone()`/`clone3()` are
blocked from creating new namespaces, `socket()` is blocked from creating
`AF_NETLINK` or `SOCK_RAW` sockets, and `execve()`/`execveat()` are validated
against `allow_execve` paths for every execution (not just the initial command).

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

## Strict Mode

Strict mode (`--strict` or `strict = true` in config) tightens all enforcement
for CI and production use. Every point where normal mode gracefully degrades
becomes a hard failure.

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
| Filesystem isolation | Falls back with warning | **Aborts** |
| Network setup | Logs warning | **Aborts** |
| Loopback bring-up | Skips with warning | **Aborts** |
| Seccomp deny action | `EPERM` (process survives) | `KILL_PROCESS` (immediate termination) |
| Cgroup setup | Logs warning | **Aborts** |

**Mutual exclusion:** `--strict` and `--monitor` cannot be used together.
Strict mode ensures full enforcement; monitor mode relaxes it. These are
contradictory intents.

---

## Allow Degraded Mode

By default, Canister **fails hard** when isolation cannot be established
(e.g., AppArmor blocks mount operations, cgroup delegation unavailable).
The `--allow-degraded` flag opts into reduced isolation instead of aborting.

**Config:**

```toml
allow_degraded = true
```

**CLI:**

```bash
can run --allow-degraded -- echo "hello"
```

The CLI `--allow-degraded` flag is OR'd with the config value — if either
is set, degraded mode is permitted.

**Changes with `--allow-degraded`:**

| Enforcement point | Default (fail-hard) | With `--allow-degraded` |
|-------------------|---------------------|------------------------|
| Filesystem isolation | **Aborts** if AppArmor blocks mounts | Falls back to host FS with warning |
| Network setup | **Aborts** on failure | Logs warning, continues |
| Loopback bring-up | **Aborts** on failure | Skips with warning |
| Cgroup setup | **Aborts** on failure | Skips with warning |

**Mutual exclusion:** `--allow-degraded` and `--strict` cannot be used
together. Strict mode demands full enforcement; degraded mode accepts
partial enforcement. These are contradictory intents.

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
| `[process].allow_execve` | Blocks unlisted commands | Logs warning, allows |
| `[process].env_passthrough` | Strips unlisted vars | Logs stripped count, passes all |
| `[process].max_pids` | Enforces RLIMIT_NPROC | Logs limit, skips enforcement |
| `[syscalls]` seccomp | Returns EPERM on denied syscalls | Logs to kernel audit, allows |
| `[filesystem]` | Overlay + pivot_root | Unchanged (isolation active) |
| `[network]` | Namespace + slirp4netns | Unchanged (isolation active) |

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
allow_degraded = false

[filesystem]
allow = ["/bin", "/sbin", "/usr/bin", ...]
deny = ["/etc/shadow", "/etc/gshadow"]

[network]
allow_domains = ["hex.pm", "repo.hex.pm", "builds.hex.pm"]
deny_all = true

[process]
allow_execve = ["/nix/store/*"]
env_passthrough = ["PATH", "HOME", ...]

[resources]

[syscalls]
seccomp_mode = "allow-list"
allow_extra = ["ptrace"]
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
deny_all = true
[syscalls]
```

### Python data science

Allow pip installs from PyPI and access to a workspace directory.

```toml
[filesystem]
allow = [
    "/usr/lib",
    "/usr/bin",
    "/usr/local/lib",
    "/tmp/workspace",
]
deny = ["/etc/shadow", "/root"]

[network]
allow_domains = [
    "pypi.org",
    "files.pythonhosted.org",
]
deny_all = true

[process]
env_passthrough = ["PATH", "HOME", "LANG", "VIRTUAL_ENV"]
```

### Node.js build

Allow npm registry access and a project directory.

```toml
[filesystem]
allow = [
    "/usr/lib",
    "/usr/bin",
    "/usr/local",
    "/home/user/project",
]

[network]
allow_domains = [
    "registry.npmjs.org",
    "nodejs.org",
]
deny_all = true

[process]
env_passthrough = ["PATH", "HOME", "NODE_ENV"]
```

### Full network trust

For trusted code that needs unrestricted network access but should still be
filesystem- and syscall-restricted.

```toml
[filesystem]
allow = ["/tmp/workspace"]

[network]
deny_all = false
```

### Air-gapped

No network, no filesystem beyond essentials, strict seccomp.

```toml
[filesystem]
allow = ["/tmp/workspace"]
deny  = ["/etc", "/root", "/home"]

[network]
deny_all = true
```

### Strict CI

All-or-nothing enforcement. If any isolation layer can't be set up, the
sandbox refuses to start. Denied syscalls kill the process immediately.

```toml
strict = true

[filesystem]
allow = ["/tmp/workspace"]

[network]
deny_all = true

[process]
max_pids = 64
allow_execve = ["/usr/bin/python3"]

[resources]
memory_mb = 512
cpu_percent = 100

[syscalls]
seccomp_mode = "allow-list"
```

### Elixir/Erlang (mix tasks, iex, Phoenix)

Run mix tasks, iex shells, or Phoenix servers with hex.pm access.
Use with `-r nix` or `-r homebrew` if Elixir is installed via a package manager.

```toml
[recipe]
name = "elixir"
description = "Elixir/Erlang (BEAM VM) — mix, iex, Phoenix"

[filesystem]
allow = [
    "/usr/lib",
    "/usr/bin",
    "/usr/local/lib",
    "/usr/local/bin",
    "/lib",
    "/tmp/workspace",
]
deny = ["/etc/shadow", "/root"]

[network]
allow_domains = ["hex.pm", "repo.hex.pm", "builds.hex.pm"]
deny_all = true

[process]
max_pids = 256
env_passthrough = [
    "PATH", "HOME", "LANG", "TERM",
    "MIX_ENV", "MIX_HOME", "HEX_HOME",
    "ERL_AFLAGS", "ELIXIR_ERL_OPTIONS",
    "SECRET_KEY_BASE", "DATABASE_URL", "PORT",
]

[syscalls]
allow_extra = ["ptrace"]   # BEAM tracing tools (:observer, :dbg, recon)
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
