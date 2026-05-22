<p align="center">
  <img width="300" alt="canister" src="https://github.com/user-attachments/assets/476d2ac9-d390-4798-b329-dd371162cd99" /><br>
  <strong>canister</strong><br>
  <em>A lightweight sandbox for running untrusted code safely on Linux.</em>
</p>

<p align="center">
  <a href="#installation">Installation</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#recipe-composition">Recipe Composition</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#configuration">Configuration</a> &middot;
  <a href="docs/ARCHITECTURE.md">Architecture</a> &middot;
  <a href="docs/CONFIGURATION.md">Config Reference</a> &middot;
  <a href="docs/DLP.md">DLP</a> &middot;
  <a href="docs/refusals.md">Refusals</a> &middot;
  <a href="docs/SECCOMP.md">Seccomp</a>
</p>

---

**Canister** (`can`) runs any command inside an isolated sandbox with restricted
filesystem, network, and syscall access. No root required. Single binary, zero
runtime dependencies.

```
$ can run --recipe recipes/example.toml -- python3 untrusted_script.py
```

The script sees an empty filesystem (except explicitly allowed paths), can
only reach allowed domains, and is blocked from dangerous syscalls like
`mount`, `ptrace`, and `reboot`. When it exits, all filesystem writes are
discarded.

## Features

- **Unprivileged** -- uses user namespaces, no root or suid binary needed
- **Filesystem isolation** -- ephemeral overlay with read-only bind mounts; writes discarded on exit
- **Project manifests** -- define named sandboxes in `canister.toml` and run them with `can up`; recipes declared per-sandbox, overrides for filesystem/network/syscalls, dry-run preview
- **Package manager support** -- auto-detects and mounts binaries from Nix, Homebrew, Guix, Snap, Cargo, and other non-standard install locations
- **Network isolation** -- three modes: no network, filtered (FQDN/IP allow list via pasta + a local L7 proxy), or full; port forwarding (`-p`); each sandbox gets its own isolated network namespace
- **Per-destination egress contracts** -- one `[[host]]` block per upstream declares the allowed methods, content types, paths, body size, and DLP credential scope; refused requests get a `415` with a copy-pasteable patch in the response body. Closes the "POST `image/png` to a JSON-only API" class of exfil. See [docs/refusals.md](docs/refusals.md).
- **DLP (Data Loss Prevention)** -- L7 proxy scans outbound HTTP for ~14 credential types (GitHub PAT, AWS access key, OpenAI / Anthropic keys, npm tokens, SSH private keys, session canaries, …) through every encoding chain (base64 / hex / percent / gzip / zlib / zstd / ascii85 / utf16-le) and structured payload format (JSON, multipart, form-urlencoded, XML, HTTP/1.1 trailers). See [docs/DLP.md](docs/DLP.md).
- **Seccomp BPF** -- default-deny allow-list syscall filtering with a single curated baseline (~187 syscalls) defined in `recipes/default.toml`; embedded in the binary, overridable on disk; recipes customize via `allow_extra` / `deny_extra`
- **Seccomp USER_NOTIF supervisor** -- argument-level syscall filtering for `connect()` (IP allowlist), `sendmsg()` (blocks SCM_RIGHTS fd passing), `clone()`/`clone3()` (deny namespace creation), `socket()` (deny raw sockets, restrict AF_NETLINK to NETLINK_ROUTE only), `execve()`/`execveat()` (enforce `allow_execve` for every exec, not just the initial command). Requires Linux 5.9+, auto-detected.
- **Process isolation** -- PID namespace with proper session setup (`setsid`), environment filtering, RLIMIT_NPROC, execve allow list with prefix rules (`/nix/store/*`)
- **Recipe composition** -- multiple `-r` flags merged left-to-right; `base.toml` provides essential OS mounts; package manager recipes auto-detected via `match_prefix`; environment variable expansion (`$HOME`, `$USER`) in paths
- **Credential protection** -- recipes explicitly deny sensitive paths (`$HOME/.ssh`, `$HOME/.gnupg`, `$HOME/.aws`, etc.); cargo credentials excluded from the cargo recipe via deny rules
- **Recipe lifecycle** -- `can init` / `can update` download community recipes from GitHub via `git clone`
- **Resource limits** -- cgroups v2 enforcement of memory and CPU limits
- **Strict mode** -- `--strict` flag for CI/production: seccomp uses KILL_PROCESS instead of EPERM, DLP scanning is implicitly enabled when `egress = "proxy-only"`, and generic high-entropy detections are promoted from Warn to Block
- **Fail-by-default** -- sandbox aborts when isolation cannot be established; all setup failures are fatal
- **Monitor mode** -- run with `--monitor` to observe what would be blocked without enforcing, then iterate on your policy
- **Recipe inspection** -- `can recipe show` emits the fully resolved policy as valid TOML for auditing or creating standalone recipes
- **Proc hardening** -- Docker-style /proc masking: /proc/kcore, /proc/keys, /proc/sysrq-trigger, /proc/key-users, /proc/kallsyms, /proc/schedstat hidden; /proc/self/mountinfo masked; /proc/sys read-only
- **Capability dropping** -- all 41 Linux capabilities dropped from the bounding set before exec; inheritable and ambient sets cleared; sandboxed processes run with completely empty capability state
- **Default resource limits** -- RLIMIT_NPROC=4096, RLIMIT_AS=8GB, RLIMIT_NOFILE=4096, RLIMIT_FSIZE=4GB, RLIMIT_CORE=0 applied before exec; overridable via recipe `[resources]` section
- **Single binary** -- pure Rust, no external library dependencies
- **MAC detection** -- detects AppArmor (Ubuntu) and SELinux (Fedora/RHEL) restrictions; auto-installs the correct security policy via `can setup`
- **TOML recipes** -- strict schema with `deny_unknown_fields`, optional `[recipe]` metadata, `[syscalls]` section for per-recipe baseline customization
- **TTY-aware logging** -- colored human output on terminals, JSON lines when piped

## Requirements

- Linux 5.6+ with unprivileged user namespaces enabled
- `pasta` from passt (only for filtered network mode)

Check your system:

```
$ can check
Kernel: 6.8.0-106-generic
  User namespaces:    available
  PID namespaces:     available
  Mount namespaces:   available
  Network namespaces: available
  Cgroups v2:         available
  OverlayFS:          available
  Seccomp BPF:        available
  pasta:              available
  seccomp:            supported

Canister can run on this system.
```

## Installation

### Pre-built binaries

Download the latest release from [GitHub Releases](https://github.com/dergraf/canister/releases):

```bash
# Install to ~/.local/bin so no sudo is needed.
# Make sure ~/.local/bin is on your PATH (most distros add it automatically).
mkdir -p ~/.local/bin
curl -fsSL https://github.com/dergraf/canister/releases/download/latest/canister-x86_64-linux.tar.gz \
  | tar xz -C ~/.local/bin
```

Verify the download:

```bash
curl -fsSL https://github.com/dergraf/canister/releases/download/latest/canister-x86_64-linux.tar.gz.sha256 | sha256sum -c
```

> **Note on privileges.** Day-to-day `can run` / `can up` invocations are
> unprivileged. Two exceptions: `can setup` needs `sudo` once on hardened
> distros (Ubuntu 24.04+, Fedora 41+) to install the AppArmor / SELinux
> policy that grants the binary user-namespace creation; and filtered
> network mode requires `pasta` (from the `passt` package) installed on
> the host — `can` itself ships no daemon.

### Build from source

```bash
# Rust toolchain is pinned via rust-toolchain.toml — rustup handles it automatically
cargo build --release
```

The binary is at `target/release/can`.

### Contributor verification

Run the same core checks as CI before opening a PR:

```bash
./ci/verify.sh
```

## Quick Start

### Project manifest (`canister.toml`)

The recommended way to use Canister is with a project manifest. Create a
`canister.toml` in your project root:

```toml
[sandbox.dev]
description = "Development shell"
recipes = ["neovim", "elixir", "nix"]
command = "nvim"

[sandbox.dev.filesystem]
allow_write = ["$HOME/.local/share/nvim"]

[sandbox.test]
description = "Test runner"
recipes = ["elixir", "nix"]
command = "mix test"

[sandbox.ci]
description = "CI — strict mode"
recipes = ["elixir", "nix", "generic-strict"]
command = "mix test --cover"
strict = true

[sandbox.ci.resources]
memory_mb = 2048
```

Then run sandboxes by name:

```bash
can up dev          # run the dev sandbox
can up test         # run tests
can up ci           # strict CI mode
can up              # runs the first sandbox alphabetically (ci)
can up dev --dry-run  # preview the resolved policy
```

### Ad-hoc sandboxing (`can run`)

For one-off commands without a manifest:

```bash
# Minimal -- default proxy-only policy, default seccomp baseline
can run -- echo "hello from the sandbox"

# With a recipe file (path)
can run --recipe recipes/example.toml -- python3 script.py

# With a recipe by name (searches ./.canister/, $XDG_CONFIG_HOME/canister/recipes/, /etc/canister/recipes/)
can run -r elixir -- mix test

# Compose multiple recipes -- merged left-to-right
can run -r nix -r elixir -- mix test
can run -r cargo -r generic-strict -- cargo build

# Commands from any package manager work automatically:
# Nix, Homebrew, Cargo, Snap, Flatpak, Guix -- prefix is auto-detected via match_prefix
can run -- iex -e 'IO.puts("hello")'        # Nix-installed Elixir
can run -- rg --help                         # Cargo-installed ripgrep

# Port forwarding -- expose sandbox ports on the host
can run -p 8080:80 -r elixir -- mix phx.server
can run -p 127.0.0.1:3000:3000 -p 5432:5432 -- my-app

# Strict mode for CI -- seccomp kills on violation instead of EPERM
can run --strict -r elixir -- mix test

# Monitor mode -- observe what would be blocked without enforcing
can run --monitor -r elixir -- mix test

# Verbose logging (debug level)
can -v run -- ls /
```

### Install community recipes

```bash
# Download recipes from the canister GitHub repository
can init

# Update to latest recipes
can update

# Use a custom recipe source
can init --repo myorg/canister-recipes --branch main
```

### Inspect seccomp baseline

```
$ can recipe list
Discovered recipes:

  elixir               Elixir/Erlang (BEAM VM) -- mix, iex, Phoenix
                       +ptrace                        recipes/elixir.toml
  nix                  Nix package manager (/nix/store)
                                                      recipes/nix.toml
  ...

Default baseline: ~187 allowed, ~18 denied syscalls
  Customize per-recipe with [syscalls] allow_extra / deny_extra
```

### Inspect resolved policy

```bash
# See the fully resolved policy after recipe merging
can recipe show -r elixir

# Save as a standalone recipe
can recipe show -r nix -r elixir > my-custom.toml
can run -r my-custom.toml -- mix test
```

## How It Works

Canister combines twelve isolation mechanisms:

```
                          can run -- python3 script.py
                                     |
                          ┌──────────┴──────────┐
                          │     fork()           │
                          │                      │
                    ┌─────┴─────┐          ┌─────┴─────┐
                    │  PARENT   │          │   CHILD    │
                    │           │          │            │
                    │ write     │  pipes   │ unshare()  │
                    │ uid/gid   │◄────────►│ USER+PID   │
                    │ maps      │          │ [+NET]     │
                    │           │          │            │
                    │ start     │          │ unshare()  │
                    │ pasta     │          │ MNT        │
                    │           │          │ fork()     │
                    │ wait()    │          │ → PID 1    │
                    │           │          │ pivot_root │
                    │           │          │ seccomp    │
                    │           │          │ env filter │
                    │           │          │ execve()   │
                    └───────────┘          └────────────┘
```

1. **User namespaces** -- the child process gets its own UID/GID mapping (host
   user maps to root inside the namespace). No actual privileges are gained.

2. **Mount namespace + pivot_root** -- an ephemeral tmpfs becomes the new root.
   Essential system paths are defined in `recipes/base.toml` (embedded, overridable)
   and bind-mounted read-only. The host's current working directory is always
   bind-mounted writable. For commands installed via Nix, Homebrew, Cargo, or
   other package managers, the install prefix is auto-detected via `match_prefix`
   rules in recipe files and mounted automatically. The host filesystem is unmounted.

3. **PID namespace** -- the sandboxed process becomes PID 1 in its own PID
   namespace. It cannot see or signal any host processes.

4. **Network namespace + pasta** -- in filtered mode, the sandbox gets
   its own network stack. `pasta` (from passt) provides user-mode TCP/IP by
   mirroring the host's network configuration into the namespace. Allowed
   domains are pre-resolved to IPs at startup.

5. **Seccomp BPF** -- a Berkeley Packet Filter program is loaded right before
   `exec`. It operates in **default-deny (allow-list) mode**: only syscalls
   explicitly listed in the profile are permitted; everything else is blocked.
   The filter validates the CPU architecture (prevents x32 ABI bypass) and
   returns `EPERM` for unlisted syscalls (or `KILL_PROCESS` in strict mode).

6. **Seccomp USER_NOTIF supervisor** -- a parent-process supervisor thread
   intercepts `connect()`, `sendto()`, `sendmsg()`, `clone()`/`clone3()`,
   `socket()`, `execve()`, and `execveat()` syscalls via `SECCOMP_RET_USER_NOTIF`.
   It reads the actual arguments from `/proc/<pid>/mem` and enforces IP allowlists,
   SCM_RIGHTS fd passing blocks, namespace creation blocks, raw socket denial,
   AF_NETLINK protocol restrictions, and `allow_execve` path validation.
   Auto-detected on Linux 5.9+.

7. **Cgroups v2** -- memory and CPU limits are enforced via the cgroup
   filesystem. Canister creates a child cgroup under the user's systemd
   delegation and writes `memory.max` and `cpu.max`. No root required.
   Resource limits are opt-in (not in shipped base recipes).

8. **/proc hardening** -- sensitive paths under `/proc` are masked (bind-mount
   `/dev/null` over files, empty tmpfs over directories) and `/proc/sys` is
   remounted read-only, matching Docker's default behavior. Additionally,
   `/proc/self/mountinfo` and `/proc/1/mountinfo` are masked to prevent
   sandbox topology leakage, and `/proc/key-users`, `/proc/kallsyms`, and
   `/proc/schedstat` are masked to reduce information exposure.

9. **Capability dropping** -- all 41 Linux capabilities are dropped from the
   bounding set using `prctl(PR_CAPBSET_DROP)` before exec. The inheritable
   and ambient capability sets are also cleared. After exec with
   `NO_NEW_PRIVS`, the sandboxed process runs with completely empty capability
   state (`CapEff=0, CapPrm=0, CapBnd=0, CapAmb=0, CapInh=0`).

10. **Default resource limits** -- conservative rlimits are applied before exec:
    RLIMIT_NPROC=4096, RLIMIT_AS=8GB, RLIMIT_NOFILE=4096, RLIMIT_FSIZE=4GB,
    RLIMIT_CORE=0. These provide defense against fork bombs, memory exhaustion,
    and core dump leakage even without explicit `[resources]` in the recipe.

11. **L7 egress proxy + contract gate** -- in `proxy-only` mode, the sandbox's
    only outbound route is a local HTTP/HTTPS proxy (the proxy port is the
    only IP the supervisor allows `connect()` to). Every request is checked
    against the matching `[[host]]` contract first — method, content-type,
    path, body-size — and refused with `415` + an actionable patch in the
    response body before any DLP scan runs.

12. **DLP scanner** -- runs inside the proxy. ~14 credential detectors
    (GitHub PAT, AWS key, OpenAI / Anthropic keys, npm token, SSH private
    keys, session canaries, …) walk every header, URI segment, JSON path,
    form value, multipart part, XML node, and HTTP/1.1 trailer through an
    encoding-chain decoder (base64 / hex / percent / gzip / zlib / zstd /
    ascii85 / utf16-le) and a normalize pass (strip separators, unicode
    normalize, unescape). Per-host `allow_credentials` lists downgrade
    legitimate flows from Block to Warn. See [docs/DLP.md](docs/DLP.md).

For a detailed walkthrough, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Recipe Composition

Canister supports composing multiple recipes via repeated `-r` flags. Recipes
are merged left-to-right with well-defined semantics:

```bash
# base.toml (always) → nix.toml (auto-detected) → elixir.toml (explicit)
can run -r nix -r elixir -- mix test
```

**Composition order:** `base.toml` → auto-detected recipes → explicit `--recipe` args.

**Name-based lookup:** `-r nix` resolves to `nix.toml` in the recipe search path
(`./.canister/`, `$XDG_CONFIG_HOME/canister/recipes/`, `/etc/canister/recipes/`).
If the argument contains `/` or `.toml`, it's treated as a file path.

**Auto-detection:** Recipes declare `match_prefix` patterns in `[recipe]` metadata.
When the resolved command binary path matches a prefix, the recipe is automatically
composed into the stack. For example, running a nix-installed `mix` auto-detects
`nix.toml` because the binary lives under `/nix/store`.

### Merge semantics

| Field type | Strategy |
|---|---|
| `Vec` fields (paths, domains, syscalls, env vars) | **Union** (deduplicated) |
| `strict` | **OR** -- any `true` wins, can never be loosened |
| `egress`, `seccomp_mode` | **Last-wins** -- `None` preserves earlier value |
| Numeric (`max_pids`, `memory_mb`, `cpu_percent`) | **Last-wins** |

### Environment variable expansion

Recipe paths support `$HOME`, `$USER`, `${XDG_CONFIG_HOME}`, and `$$` (literal `$`):

```toml
[filesystem]
allow = ["$HOME/.cargo", "$HOME/.rustup"]

[recipe]
match_prefix = ["$HOME/.cargo"]
```

### Package manager recipes

| Recipe | Auto-detected when binary is under |
|--------|-----------------------------------|
| `package-managers/nix` | `/nix/store` |
| `package-managers/homebrew` | `/opt/homebrew`, `/home/linuxbrew/.linuxbrew` |
| `package-managers/cargo` | `$HOME/.cargo`, `$HOME/.rustup` |
| `package-managers/snap` | `/snap` |
| `package-managers/flatpak` | `/var/lib/flatpak`, `$HOME/.local/share/flatpak` |
| `package-managers/gnu-store` | `/gnu/store` |

These replace hardcoded prefix detection — adding support for a new
package manager is "write a .toml file" not "modify Rust code".

### Recipe categories — strict, composable, least-privilege

Recipes live in category subdirectories under `recipes/`. The category
is the directory name; there is no `kind` / `tool:` / `service:`
distinction — every entry is just a recipe.

The split is **strict** so every recipe stays single-purpose. A recipe
in `languages/` covers only what the runtime needs to *execute*. A
recipe in `package-managers/` covers cache dirs, config, and
credential handling — never registry domains. The **only** recipes that
open a network destination are under `recipes/services/`, one per
upstream. To do anything useful you **compose** explicitly:

```toml
[sandbox.python]
recipes = ["python", "pip", "pypi"]    # run python3 + install from PyPI
command = "python3 -m pip install -r requirements.txt"

[sandbox.python.network]
egress = "proxy-only"
```

```toml
[sandbox.rust]
recipes = ["cargo", "crates-io", "rust-lang"]   # build + fetch + rustup
command = "cargo build --release"
```

```toml
[sandbox.elixir]
recipes = ["elixir", "hex", "github"]   # mix + Hex deps + GitHub-hosted deps
command = "mix deps.get"
```

This way a recipe can never *imply* a network destination you didn't
ask for, and the audit story is straightforward: the manifest is the
complete picture of what a sandbox can reach.

| Directory               | What it ships                                                 | Example usage                                  |
|-------------------------|---------------------------------------------------------------|------------------------------------------------|
| `recipes/languages/`    | Programming-language runtimes — interpreter / compiler only (python, node, elixir, go) | `recipes = ["python", "pip", "pypi"]`          |
| `recipes/package-managers/` | OS PMs + language-ecosystem PMs + toolchain managers (cargo, rustup, npm, pip, poetry, pnpm, yarn, uv, homebrew, nix, snap, flatpak, gnu-store) — filesystem/config only, no registry hosts | `recipes = ["nix", "pip", "pypi"]`             |
| `recipes/vcs/`          | Version-control clients (git, gh)                              | `recipes = ["git", "gh", "github"]`            |
| `recipes/container/`    | Container tooling configs that don't require a local runtime (podman-config, kubectl, helm) | `recipes = ["kubectl"]`                        |
| `recipes/editors/`      | Editor bundles (neovim, opencode)                              | `recipes = ["neovim", "github", "luarocks"]`   |
| `recipes/system/`       | System & auth helpers (ssh-agent, gpg-public, generic-strict)  | `recipes = ["gpg-public", "gpg-keyservers"]`   |
| `recipes/services/`     | Per-upstream `[[host]]` contracts — the **only** recipes that open network destinations (github, openai, anthropic, npm-registry, pypi, hex, crates-io, rust-lang, go-proxy, yarn-registry, luarocks, opencode-ai, gpg-keyservers, huggingface, aws, stripe, slack) | `recipes = ["github", "openai"]`               |

A service contract refusing a request emits a 415 with a copy-pasteable
`[[host]]` patch in the body — paste the three lines into your
`canister.toml` to extend the contract for your project.

## Configuration

Canister uses TOML recipe files. All fields have sensible defaults.
Unknown fields are rejected. Recipes can include a `[recipe]` metadata
section and a `[syscalls]` section to customize the seccomp baseline.

```toml
[recipe]
name = "my-policy"
description = "Policy for my project"
match_prefix = ["/nix/store"]  # auto-detect when binary is under this path

[filesystem]
allow = ["/usr/lib", "/usr/bin", "/tmp/workspace", "$HOME/.config"]
deny  = ["/etc/shadow"]

[network]
egress        = "proxy-only"        # default
allow_ips     = ["10.0.0.0/8"]      # IP-literal egress
contract_mode = "strict"            # default; refuse hosts with no [[host]] block

# One [[host]] per upstream — see docs/refusals.md.
[[host]]
domain        = "pypi.org"
methods       = ["GET", "HEAD"]
content_types = ["application/json"]

[[host]]
domain = "files.pythonhosted.org"   # CDN; minimal block = allow with no shape gate

[process]
max_pids        = 64
allow_execve    = ["/usr/bin/python3", "/nix/store/*"]  # prefix rules with /*
env_passthrough = ["PATH", "HOME", "LANG"]

[resources]
memory_mb   = 512
cpu_percent = 50

[syscalls]
seccomp_mode = "allow-list"     # default; or "deny-list"
allow_extra  = ["ptrace"]       # add to the default baseline
deny_extra   = ["personality"]  # remove from the baseline and explicitly deny
```

For complete reference, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Network Modes

The network mode is determined from `[network].egress` plus allowlists/ports:

| Config | Mode | Behavior |
|--------|------|----------|
| `egress = "none"` | **None** | Empty network namespace, loopback only |
| `egress = "proxy-only"` | **Filtered** | Outbound HTTP/HTTPS must use the local L7 proxy; direct egress blocked; the contract gate refuses any request that doesn't match a `[[host]]` block (default `contract_mode = "strict"`) |
| `egress = "direct"` (no allowlists/ports) | **Full** | No network isolation (trust mode) |
| `egress = "direct"` (with allowlists/ports) | **Filtered** | Direct egress with seccomp policy checks against pre-resolved `[[host]]` IPs and `allow_ips` |

Filtered mode requires `pasta` installed (`sudo apt install passt` on Debian/Ubuntu, `sudo dnf install passt` on Fedora).

In `proxy-only` mode (the default), the contract gate runs **before**
the DLP scanner: a `POST image/png` to a JSON-only API is refused
with a `415` + a copy-pasteable patch in the response body, without
ever decoding the request body. See [docs/refusals.md](docs/refusals.md)
for the operator walkthrough.

### Port Forwarding

Use `-p` / `--port` to forward ports from the host into the sandbox (Docker-compatible syntax):

```bash
# Forward host port 8080 to sandbox port 80
can run -p 8080:80 -r my-recipe -- my-server

# Bind to a specific host IP
can run -p 127.0.0.1:3000:3000 -- my-app

# Forward UDP
can run -p 5353:53/udp -- dns-server

# Multiple ports
can run -p 8080:80 -p 8443:443 -- nginx
```

Syntax: `-p [ip:]hostPort:containerPort[/protocol]`

Port forwarding automatically enables filtered network mode.

## Security Model

Canister is defense-in-depth. Each layer independently restricts the sandboxed process:

| Layer | What it restricts | Bypass requires |
|-------|-------------------|-----------------|
| User namespace | No real root privileges | Kernel exploit |
| Mount namespace | Filesystem view | Mount escape (blocked by seccomp) |
| Network namespace | Network access | Namespace escape (blocked by seccomp) |
| Seccomp BPF (allow-list) | Syscall access (default deny) | Filter bypass (architecture-validated) |
| USER_NOTIF supervisor | connect() IPs, sendmsg() SCM_RIGHTS, clone() flags, socket() types, execve() paths | Kernel exploit or TOCTOU race |
| PID namespace | Process visibility | Namespace escape (blocked by seccomp) |
| Cgroups v2 | Memory and CPU usage | Cgroup escape (requires root) |
| /proc hardening | Sensitive kernel info, mountinfo topology | Remount (blocked by seccomp) |
| Capability dropping | All 41 capabilities dropped from bounding set | Kernel exploit |
| Default resource limits | Fork bombs, memory exhaustion, core dumps | Kernel exploit |
| Environment filtering | Host env leakage | N/A (applied at exec) |
| RLIMIT_NPROC | Fork bombs | Kernel exploit |
| Read-only bind mounts | Write access | Remount (blocked by seccomp) |
| Contract gate (`[[host]]`) | Wrong request shape (method / CT / path / size) to a known upstream | A `[[host]]` block that explicitly permits the shape |
| DLP scanner | Outbound credential bytes (post decode chain + normalize) | A novel credential pattern, an unknown encoding, or a host with explicit `allow_credentials` |

**What Canister does NOT protect against:**

- Kernel exploits (no sandbox can)
- Side-channel attacks (timing, cache)
- Attacks within the allowed surface (if you allow `/`, there's no filesystem isolation)

## Threat Model

Canister is designed to sandbox **untrusted but non-malicious-kernel-level
code** — scripts, build tools, and applications that may misbehave but are
not expected to carry kernel exploits.

**In scope (Canister defends against):**

- Untrusted code reading/writing files outside the sandbox
- Untrusted code accessing the network without authorization
- Untrusted code connecting to unauthorized IPs (USER_NOTIF supervisor intercepts `connect()`)
- Untrusted code calling dangerous syscalls (module loading, rebooting, etc.)
- Untrusted code seeing or signaling host processes
- Untrusted code consuming unbounded memory or CPU
- Untrusted code leaking host environment variables (API keys, tokens)
- Untrusted code executing unauthorized binaries (USER_NOTIF intercepts `execve()`/`execveat()`)
- Untrusted code sending the wrong shape of request to a known upstream — `POST image/png` to a JSON-only API, `DELETE` to a read-only API, oversize uploads (contract gate)
- Untrusted code exfiltrating credentials over HTTP — even when wrapped in `base64(gzip(strip_separators(token)))` or hidden in HTTP/1.1 trailers, multipart parts, XML attributes, or form values (DLP scanner)
- Fork bombs and resource exhaustion within the sandbox
- x32 ABI syscall bypass attempts
- Namespace escape via clone/clone3 flags (USER_NOTIF blocks namespace creation)

**Out of scope (Canister does NOT defend against):**

- **Kernel exploits.** If the attacker has a kernel 0-day, no userspace
  sandbox helps. Seccomp reduces attack surface but cannot eliminate it.
- **Side-channel attacks.** Timing, cache, and speculative execution attacks
  are fundamentally out of scope for process-level sandboxing.
- **Monitor mode poisoning.** Monitor mode (`--monitor`) provides no security.
  A malicious process aware it's being monitored can behave differently.
  Always validate policies with enforcement enabled before trusting them.

**Strict mode** (`--strict`) is recommended for CI and production. It uses
`SECCOMP_RET_KILL_PROCESS` instead of `SECCOMP_RET_ERRNO`, ensuring
immediate process termination on any denied syscall rather than returning
an error code the process could handle.

## Security Policies (AppArmor / SELinux)

Some distributions restrict mount operations inside unprivileged user namespaces
via Mandatory Access Control:

- **Ubuntu 24.04+**: AppArmor (`apparmor_restrict_unprivileged_userns=1`)
- **Fedora 41+ / RHEL 10+**: SELinux (`user_namespace { create }` permission)
- **Arch, Void, Gentoo, etc.**: No restriction — works natively

Canister detects the active MAC system and aborts with a clear error if a policy
is needed but not installed.

```bash
# Install the security policy (auto-detects MAC system and binary path)
# Interactive: shows the policy, asks for confirmation before writing
sudo can setup

# Force reinstall (e.g., after upgrading canister)
sudo can setup --force

# Check policy status
can check

# Remove the policy
sudo can setup --remove
```

**AppArmor:** The profile grants the `can` binary mount/capability permissions
and transitions sandboxed child processes to a restricted sub-profile
(`canister_sandboxed`) that denies all capabilities, mount operations, and user
namespace creation. Trusted helper binaries (pasta, apparmor_parser) run
unconfined via specific `ux` rules.

**SELinux:** The policy module defines `canister_t` (supervisor domain) and
`canister_sandboxed_t` (restricted child domain) with appropriate type
transitions and permission grants.

## Project Structure

```
canister/
├── crates/
│   ├── can-cli/        # CLI binary (clap): commands, can up, recipe resolution, can init/update
│   ├── can-sandbox/    # Core runtime: namespaces, overlay, seccomp, USER_NOTIF supervisor, process control
│   ├── can-policy/     # Config parsing, recipe merge, manifest (canister.toml), env var expansion
│   ├── can-net/        # Network isolation: netns, pasta, DNS proxy
│   ├── can-proxy/      # L7 egress proxy: outbound policy, contract gate, MITM TLS, DLP enforcement
│   ├── can-dlp/        # DLP detection engine: detector registry, encoding-chain decoder, structured walkers, proptest harness
│   ├── can-docgen/     # mdBook reference generator (config.md, manifest.md, merge.md, recipes.md, cli.md)
│   └── can-log/        # TTY-aware structured logging
├── recipes/
│   ├── default.toml          # Default seccomp baseline (embedded + overridable)
│   ├── base.toml             # Essential OS bind mounts (embedded + overridable)
│   ├── example.toml          # Example recipe (all options documented)
│   ├── checksums.toml        # SHA-256 pinning for shipped recipes (R16 trust)
│   ├── languages/            # Programming-language runtimes — interpreter/compiler only (python, node, elixir, go)
│   ├── package-managers/     # OS PMs + language-ecosystem PMs + toolchain managers (cargo, rustup, npm, pip, poetry, pnpm, yarn, uv, homebrew, nix, snap, flatpak, gnu-store)
│   ├── vcs/                  # Version-control clients (git, gh)
│   ├── container/            # Container tooling configs that work without a local runtime (podman-config, kubectl, helm)
│   ├── editors/              # Editor bundles (neovim, opencode)
│   ├── system/               # System & auth helpers (ssh-agent, gpg-public, generic-strict)
│   └── services/             # Per-upstream [[host]] contracts (github, openai, anthropic, npm-registry, pypi, huggingface, docker, aws, stripe, slack)
├── docs/
│   ├── ARCHITECTURE.md    # Design and execution flow
│   ├── CONFIGURATION.md   # Complete config reference (incl. canister.toml + [[host]])
│   ├── SECCOMP.md         # Seccomp baseline and filtering docs
│   ├── DLP.md             # DLP threat model + detector list
│   ├── DLP-PROPTEST.md    # How the DLP proptest harness works
│   ├── refusals.md        # Operator-facing 415-vs-451 guide
│   └── adr/               # Architecture Decision Records (0001–0007)
├── tests/
│   └── integration/    # Bash integration tests (32 test files)
└── .github/
    └── workflows/      # CI configuration
```

## Development

```bash
# Prerequisites — rust-toolchain.toml pins the version, rustup installs it automatically
rustup show

# Build
cargo build --workspace

# Test
cargo test --workspace

# Integration tests (requires built binary + Linux namespaces)
cargo build --workspace && ./tests/integration/run.sh

# Lint
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format
cargo fmt --all --check  # check
cargo fmt --all          # fix
```

## License

Apache-2.0
