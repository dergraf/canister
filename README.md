<p align="center">
  <img width="300" alt="canister" src="https://github.com/user-attachments/assets/476d2ac9-d390-4798-b329-dd371162cd99" /><br>
  <strong>canister</strong><br>
  <em>A lightweight sandbox for running untrusted code safely on Linux.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#recipe-composition">Recipe Composition</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#configuration">Configuration</a> &middot;
  <a href="docs/ARCHITECTURE.md">Architecture</a> &middot;
  <a href="docs/CONFIGURATION.md">Config Reference</a> &middot;
  <a href="docs/SECCOMP.md">Seccomp Filtering</a>
</p>

---

**Canister** (`can`) runs any command inside an isolated sandbox with restricted
filesystem, network, and syscall access. No root required. Single binary, zero
runtime dependencies.

```
$ can run --recipe recipes/example.toml -- python3 untrusted_script.py
```

The script sees an empty filesystem (except explicitly whitelisted paths), can
only reach whitelisted domains, and is blocked from dangerous syscalls like
`mount`, `ptrace`, and `reboot`. When it exits, all filesystem writes are
discarded.

## Features

- **Unprivileged** -- uses user namespaces, no root or suid binary needed
- **Filesystem isolation** -- ephemeral overlay with read-only bind mounts; writes discarded on exit
- **Package manager support** -- auto-detects and mounts binaries from Nix, Homebrew, Guix, Snap, Cargo, and other non-standard install locations
- **Network isolation** -- three modes: no network, filtered (domain/IP whitelist via slirp4netns), or full
- **Seccomp BPF** -- default-deny allow-list syscall filtering with a single curated baseline (~170 syscalls) defined in `recipes/default.toml`; embedded in the binary, overridable on disk; recipes customize via `allow_extra` / `deny_extra`
- **Process isolation** -- PID namespace with proper session setup (`setsid`), environment filtering, RLIMIT_NPROC, execve whitelisting with prefix rules (`/nix/store/*`)
- **Recipe composition** -- multiple `-r` flags merged left-to-right; `base.toml` provides essential OS mounts; package manager recipes auto-detected via `match_prefix`; environment variable expansion (`$HOME`, `$USER`) in paths
- **Recipe lifecycle** -- `can init` / `can update` download community recipes from GitHub via `git clone`
- **Resource limits** -- cgroups v2 enforcement of memory and CPU limits
- **Strict mode** -- `--strict` flag for CI/production: seccomp uses KILL_PROCESS, all degradation is fatal
- **Monitor mode** -- run with `--monitor` to observe what would be blocked without enforcing, then iterate on your policy
- **Proc hardening** -- Docker-style /proc masking: /proc/kcore, /proc/keys, /proc/sysrq-trigger hidden; /proc/sys read-only
- **Single binary** -- pure Rust, no external library dependencies
- **Graceful degradation** -- detects AppArmor restrictions and falls back to reduced isolation with clear warnings
- **TOML recipes** -- strict schema with `deny_unknown_fields`, optional `[recipe]` metadata, `[syscalls]` section for per-recipe baseline customization
- **TTY-aware logging** -- colored human output on terminals, JSON lines when piped

## Requirements

- Linux 5.6+ with unprivileged user namespaces enabled
- `slirp4netns` (only for filtered network mode)

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
  slirp4netns:        available
  seccomp:            supported

Canister can run on this system.
```

## Quick Start

### Build

```
# Using mise (recommended)
mise install
mise run build

# Or plain cargo
cargo build --release
```

The binary is at `target/release/can`.

### Run a command in the sandbox

```bash
# Minimal -- default deny-all policy, default seccomp baseline
can run -- echo "hello from the sandbox"

# With a recipe file (path)
can run --recipe recipes/example.toml -- python3 script.py

# With a recipe by name (searches ./recipes/, $XDG_CONFIG_HOME/canister/recipes/, /etc/canister/recipes/)
can run -r elixir -- mix test

# Compose multiple recipes -- merged left-to-right
can run -r nix -r elixir -- mix test
can run -r cargo -r generic-strict -- cargo build

# Commands from any package manager work automatically:
# Nix, Homebrew, Cargo, Snap, Flatpak, Guix -- prefix is auto-detected via match_prefix
can run -- iex -e 'IO.puts("hello")'        # Nix-installed Elixir
can run -- rg --help                         # Cargo-installed ripgrep

# Strict mode for CI -- all degradation is fatal, seccomp kills on violation
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
$ can recipes
Discovered recipes:

  elixir               Elixir/Erlang (BEAM VM) -- mix, iex, Phoenix
                       +ptrace                        recipes/elixir.toml
  nix                  Nix package manager (/nix/store)
                                                      recipes/nix.toml
  ...

Default baseline: ~170 allowed, ~16 denied syscalls
  Customize per-recipe with [syscalls] allow_extra / deny_extra
```

## How It Works

Canister combines seven Linux isolation mechanisms:

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
                    │ uid/gid   │◄────────►│ USER+MNT   │
                    │ maps      │          │ +PID+[NET] │
                    │           │          │            │
                    │ start     │          │ fork()     │
                    │ slirp4netns          │ → PID 1    │
                    │           │          │ pivot_root │
                    │ wait()    │          │ seccomp    │
                    │           │          │ env filter │
                    │           │          │ execve()   │
                    └───────────┘          └────────────┘
```

1. **User namespaces** -- the child process gets its own UID/GID mapping (host
   user maps to root inside the namespace). No actual privileges are gained.

2. **Mount namespace + pivot_root** -- an ephemeral tmpfs becomes the new root.
   Essential system paths are defined in `recipes/base.toml` (embedded, overridable)
   and bind-mounted read-only. For commands installed via Nix, Homebrew, Cargo, or
   other package managers, the install prefix is auto-detected via `match_prefix`
   rules in recipe files and mounted automatically. The host filesystem is unmounted.

3. **PID namespace** -- the sandboxed process becomes PID 1 in its own PID
   namespace. It cannot see or signal any host processes.

4. **Network namespace + slirp4netns** -- in filtered mode, the sandbox gets
   its own network stack. `slirp4netns` provides user-mode TCP/IP from the
   parent side. Whitelisted domains are pre-resolved to IPs at startup.

5. **Seccomp BPF** -- a Berkeley Packet Filter program is loaded right before
   `exec`. It operates in **default-deny (allow-list) mode**: only syscalls
   explicitly listed in the profile are permitted; everything else is blocked.
   The filter validates the CPU architecture (prevents x32 ABI bypass) and
   returns `EPERM` for unlisted syscalls (or `KILL_PROCESS` in strict mode).

6. **Cgroups v2** -- memory and CPU limits are enforced via the cgroup
   filesystem. Canister creates a child cgroup under the user's systemd
   delegation and writes `memory.max` and `cpu.max`. No root required.

7. **/proc hardening** -- sensitive paths under `/proc` are masked (bind-mount
   `/dev/null` over files, empty tmpfs over directories) and `/proc/sys` is
   remounted read-only, matching Docker's default behavior.

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
(`./recipes/`, `$XDG_CONFIG_HOME/canister/recipes/`, `/etc/canister/recipes/`).
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
| `deny_all`, `seccomp_mode` | **Last-wins** -- `None` preserves earlier value |
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
| `nix.toml` | `/nix/store` |
| `homebrew.toml` | `/opt/homebrew`, `/home/linuxbrew/.linuxbrew` |
| `cargo.toml` | `$HOME/.cargo`, `$HOME/.rustup` |
| `snap.toml` | `/snap` |
| `flatpak.toml` | `/var/lib/flatpak`, `$HOME/.local/share/flatpak` |
| `gnu-store.toml` | `/gnu/store` |

These replace hardcoded prefix detection -- adding support for a new package
manager is "write a .toml file" not "modify Rust code".

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
allow_domains = ["pypi.org", "files.pythonhosted.org"]
allow_ips     = ["10.0.0.0/8"]
deny_all      = true   # default

[process]
max_pids       = 64
allow_execve   = ["/usr/bin/python3", "/nix/store/*"]  # prefix rules with /*
env_passthrough = ["PATH", "HOME", "LANG"]

[resources]
memory_mb   = 512
cpu_percent = 50

[syscalls]
seccomp_mode = "allow-list"  # default; or "deny-list"
allow_extra  = ["ptrace"]    # add to the default baseline
deny_extra   = ["personality"] # remove from the baseline and explicitly deny
```

For complete reference, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Network Modes

The network mode is determined automatically from the `[network]` config:

| Config | Mode | Behavior |
|--------|------|----------|
| `deny_all = true`, no allowlists | **None** | Empty network namespace, loopback only |
| `deny_all = true`, with allowlists | **Filtered** | slirp4netns provides connectivity, domains pre-resolved |
| `deny_all = false` | **Full** | No network isolation (trust mode) |

Filtered mode requires `slirp4netns` installed (`sudo apt install slirp4netns`).

## Security Model

Canister is defense-in-depth. Each layer independently restricts the sandboxed process:

| Layer | What it restricts | Bypass requires |
|-------|-------------------|-----------------|
| User namespace | No real root privileges | Kernel exploit |
| Mount namespace | Filesystem view | Mount escape (blocked by seccomp) |
| Network namespace | Network access | Namespace escape (blocked by seccomp) |
| Seccomp BPF (allow-list) | Syscall access (default deny) | Filter bypass (architecture-validated) |
| PID namespace | Process visibility | Namespace escape (blocked by seccomp) |
| Cgroups v2 | Memory and CPU usage | Cgroup escape (requires root) |
| /proc hardening | Sensitive kernel info | Remount (blocked by seccomp) |
| Environment filtering | Host env leakage | N/A (applied at exec) |
| RLIMIT_NPROC | Fork bombs | Kernel exploit |
| Read-only bind mounts | Write access | Remount (blocked by seccomp) |

**What Canister does NOT protect against:**

- Kernel exploits (no sandbox can)
- Side-channel attacks (timing, cache)
- Attacks within the allowed surface (if you whitelist `/`, there's no filesystem isolation)

## Threat Model

Canister is designed to sandbox **untrusted but non-malicious-kernel-level
code** — scripts, build tools, and applications that may misbehave but are
not expected to carry kernel exploits.

**In scope (Canister defends against):**

- Untrusted code reading/writing files outside the sandbox
- Untrusted code accessing the network without authorization
- Untrusted code calling dangerous syscalls (module loading, rebooting, etc.)
- Untrusted code seeing or signaling host processes
- Untrusted code consuming unbounded memory or CPU
- Untrusted code leaking host environment variables (API keys, tokens)
- Fork bombs and resource exhaustion within the sandbox
- x32 ABI syscall bypass attempts

**Out of scope (Canister does NOT defend against):**

- **Kernel exploits.** If the attacker has a kernel 0-day, no userspace
  sandbox helps. Seccomp reduces attack surface but cannot eliminate it.
- **Side-channel attacks.** Timing, cache, and speculative execution attacks
  are fundamentally out of scope for process-level sandboxing.
- **IP-level network filtering.** Whitelisted domains are DNS-resolved at
  startup, but connect() calls are not yet filtered by IP. A sandboxed
  process in "filtered" network mode can connect to any IP reachable via
  slirp4netns. IP-level enforcement requires `SECCOMP_RET_USER_NOTIF`
  (planned).
- **Ongoing execve enforcement.** `allow_execve` validates the initial
  command, but child processes inside the sandbox can exec arbitrary visible
  binaries. Full enforcement requires `SECCOMP_RET_USER_NOTIF` (planned).
- **Monitor mode poisoning.** Monitor mode (`--monitor`) provides no security.
  A malicious process aware it's being monitored can behave differently.
  Always validate policies with enforcement enabled before trusting them.

**Strict mode** (`--strict`) is recommended for CI and production. It
converts all graceful degradation into hard failures and uses
`SECCOMP_RET_KILL_PROCESS` instead of `SECCOMP_RET_ERRNO`, ensuring the
sandbox either runs at full strength or doesn't run at all.

## AppArmor (Ubuntu 24.04+)

Ubuntu 24.04+ restricts mount operations inside unprivileged user namespaces
via AppArmor. Canister detects this and falls back to degraded mode (no
filesystem isolation, with clear warnings).

To enable full isolation, install the override profile:

```bash
sudo cp canister.apparmor /etc/apparmor.d/local/unprivileged_userns
sudo apparmor_parser -r /etc/apparmor.d/unprivileged_userns
```

## Project Structure

```
canister/
├── crates/
│   ├── can-cli/        # CLI binary (clap): commands, recipe resolution, can init/update
│   ├── can-sandbox/    # Core runtime: namespaces, overlay, seccomp, process control
│   ├── can-policy/     # Config parsing, recipe merge, whitelist logic, env var expansion
│   ├── can-net/        # Network isolation: netns, slirp4netns, DNS proxy
│   └── can-log/        # TTY-aware structured logging
├── recipes/
│   ├── default.toml    # Default seccomp baseline (embedded + overridable)
│   ├── base.toml       # Essential OS bind mounts (embedded + overridable)
│   ├── nix.toml        # Nix package manager (auto-detected)
│   ├── homebrew.toml   # Homebrew/Linuxbrew (auto-detected)
│   ├── cargo.toml      # Rust/Cargo toolchain (auto-detected)
│   ├── snap.toml       # Snap packages (auto-detected)
│   ├── flatpak.toml    # Flatpak applications (auto-detected)
│   ├── gnu-store.toml  # GNU Guix (auto-detected)
│   ├── elixir.toml     # Elixir/Erlang development recipe
│   ├── example.toml    # Example recipe (all options documented)
│   ├── python-pip.toml # Python pip install recipe
│   ├── node-build.toml # Node.js build recipe
│   └── generic-strict.toml # Strict deny-all recipe for CI
├── docs/
│   ├── ARCHITECTURE.md # Design and execution flow
│   ├── CONFIGURATION.md# Complete config reference
│   ├── SECCOMP.md      # Seccomp baseline and filtering docs
│   └── adr/            # Architecture Decision Records
│       ├── 0001-recipes-over-profiles.md
│       └── 0002-recipe-composition-and-lifecycle.md
├── tests/
│   └── integration/    # Bash integration tests (15 test files)
└── canister.apparmor   # AppArmor override for Ubuntu 24.04+
```

## Development

```bash
# Prerequisites
mise install           # or: rustup install 1.93

# Build
mise run build         # or: cargo build --workspace

# Test
mise run test          # or: cargo test --workspace

# Lint
mise run lint          # or: cargo clippy --workspace -- -D warnings

# Format
mise run fmt           # check
mise run fmt-fix       # fix
```

## License

Apache-2.0
