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
- **Project manifests** -- define named sandboxes in `canister.toml` and run them with `can up`; recipes declared per-sandbox, overrides for filesystem/network/syscalls, dry-run preview
- **Package manager support** -- auto-detects and mounts binaries from Nix, Homebrew, Guix, Snap, Cargo, and other non-standard install locations
- **Network isolation** -- three modes: no network, filtered (domain/IP whitelist via pasta), or full; port forwarding (`-p`); each sandbox gets its own isolated network namespace
- **Seccomp BPF** -- default-deny allow-list syscall filtering with a single curated baseline (~187 syscalls) defined in `recipes/default.toml`; embedded in the binary, overridable on disk; recipes customize via `allow_extra` / `deny_extra`
- **Seccomp USER_NOTIF supervisor** -- argument-level syscall filtering for `connect()` (IP allowlist), `clone()`/`clone3()` (deny namespace creation), `socket()` (deny raw/netlink), `execve()`/`execveat()` (enforce `allow_execve` for every exec, not just the initial command). Requires Linux 5.9+, auto-detected.
- **Process isolation** -- PID namespace with proper session setup (`setsid`), environment filtering, RLIMIT_NPROC, execve whitelisting with prefix rules (`/nix/store/*`)
- **Recipe composition** -- multiple `-r` flags merged left-to-right; `base.toml` provides essential OS mounts; package manager recipes auto-detected via `match_prefix`; environment variable expansion (`$HOME`, `$USER`) in paths
- **Credential protection** -- recipes explicitly deny sensitive paths (`$HOME/.ssh`, `$HOME/.gnupg`, `$HOME/.aws`, etc.); cargo credentials excluded from the cargo recipe via deny rules
- **Recipe lifecycle** -- `can init` / `can update` download community recipes from GitHub via `git clone`
- **Resource limits** -- cgroups v2 enforcement of memory and CPU limits
- **Strict mode** -- `--strict` flag for CI/production: seccomp uses KILL_PROCESS instead of EPERM
- **Fail-by-default** -- sandbox aborts when isolation cannot be established; all setup failures are fatal
- **Monitor mode** -- run with `--monitor` to observe what would be blocked without enforcing, then iterate on your policy
- **Recipe inspection** -- `can recipe show` emits the fully resolved policy as valid TOML for auditing or creating standalone recipes
- **Proc hardening** -- Docker-style /proc masking: /proc/kcore, /proc/keys, /proc/sysrq-trigger hidden; /proc/sys read-only
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
curl -fsSL https://github.com/dergraf/canister/releases/latest/download/canister-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv can /usr/local/bin/
```

Verify the download:

```bash
curl -fsSL https://github.com/dergraf/canister/releases/latest/download/canister-x86_64-unknown-linux-gnu.tar.gz.sha256 | sha256sum -c
```

### Build from source

```bash
# Rust toolchain is pinned via rust-toolchain.toml — rustup handles it automatically
cargo build --release
```

The binary is at `target/release/can`.

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

Canister combines eight Linux isolation mechanisms:

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
   mirroring the host's network configuration into the namespace. Whitelisted
   domains are pre-resolved to IPs at startup.

5. **Seccomp BPF** -- a Berkeley Packet Filter program is loaded right before
   `exec`. It operates in **default-deny (allow-list) mode**: only syscalls
   explicitly listed in the profile are permitted; everything else is blocked.
   The filter validates the CPU architecture (prevents x32 ABI bypass) and
   returns `EPERM` for unlisted syscalls (or `KILL_PROCESS` in strict mode).

6. **Seccomp USER_NOTIF supervisor** -- a parent-process supervisor thread
   intercepts `connect()`, `clone()`/`clone3()`, `socket()`, `execve()`, and
   `execveat()` syscalls via `SECCOMP_RET_USER_NOTIF`. It reads the actual
   arguments from `/proc/<pid>/mem` and enforces IP allowlists, namespace
   creation blocks, raw socket denial, and `allow_execve` path validation.
   Auto-detected on Linux 5.9+.

7. **Cgroups v2** -- memory and CPU limits are enforced via the cgroup
   filesystem. Canister creates a child cgroup under the user's systemd
   delegation and writes `memory.max` and `cpu.max`. No root required.
   Resource limits are opt-in (not in shipped base recipes).

8. **/proc hardening** -- sensitive paths under `/proc` are masked (bind-mount
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
| `deny_all = true`, with allowlists | **Filtered** | pasta provides connectivity, domains pre-resolved |
| `deny_all = false` | **Full** | No network isolation (trust mode) |

Filtered mode requires `pasta` installed (`sudo apt install passt` on Debian/Ubuntu, `sudo dnf install passt` on Fedora).

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
| USER_NOTIF supervisor | connect() IPs, clone() flags, socket() types, execve() paths | Kernel exploit or TOCTOU race |
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
- Untrusted code connecting to unauthorized IPs (USER_NOTIF supervisor intercepts `connect()`)
- Untrusted code calling dangerous syscalls (module loading, rebooting, etc.)
- Untrusted code seeing or signaling host processes
- Untrusted code consuming unbounded memory or CPU
- Untrusted code leaking host environment variables (API keys, tokens)
- Untrusted code executing unauthorized binaries (USER_NOTIF intercepts `execve()`/`execveat()`)
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
│   ├── can-sandbox/    # Core runtime: namespaces, overlay, seccomp, process control
│   ├── can-policy/     # Config parsing, recipe merge, manifest (canister.toml), env var expansion
│   ├── can-net/        # Network isolation: netns, pasta, DNS proxy
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
│   ├── opencode.toml   # OpenCode AI coding agent recipe
│   ├── example.toml    # Example recipe (all options documented)
│   ├── python-pip.toml # Python pip install recipe
│   ├── node-build.toml # Node.js build recipe
│   └── generic-strict.toml # Strict deny-all recipe for CI
├── docs/
│   ├── ARCHITECTURE.md # Design and execution flow
│   ├── CONFIGURATION.md# Complete config reference (incl. canister.toml)
│   ├── SECCOMP.md      # Seccomp baseline and filtering docs
│   └── adr/            # Architecture Decision Records
│       ├── 0001-recipes-over-profiles.md
│       ├── 0002-recipe-composition-and-lifecycle.md
│       └── 0005-project-manifest-and-recipe-sources.md
├── tests/
│   └── integration/    # Bash integration tests (15 test files)
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
