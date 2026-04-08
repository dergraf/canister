<p align="center">
  <img width="300" alt="canister" src="https://github.com/user-attachments/assets/476d2ac9-d390-4798-b329-dd371162cd99" /><br>
  <strong>canister</strong><br>
  <em>A lightweight sandbox for running untrusted code safely on Linux.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
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
- **Seccomp BPF** -- default-deny allow-list syscall filtering with a single curated baseline (~130 syscalls) defined in `recipes/default.toml`; embedded in the binary, overridable on disk; recipes customize via `allow_extra` / `deny_extra`
- **Process isolation** -- PID namespace, environment filtering, RLIMIT_NPROC, execve whitelisting
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

# With a recipe file
can run --recipe recipes/example.toml -- python3 script.py

# Strict mode for CI -- all degradation is fatal, seccomp kills on violation
can run --strict --recipe recipes/example.toml -- python3 script.py

# Elixir/Erlang -- run mix tasks or iex (recipe adds ptrace to baseline)
can run --recipe recipes/elixir.toml -- mix test
can run --recipe recipes/elixir.toml -- iex -S mix

# Commands from any package manager work automatically:
# Nix, Homebrew, Cargo, pipx, etc. -- prefix is auto-detected and mounted
can run -- iex -e 'IO.puts("hello")'        # Nix-installed Elixir
can run -- rg --help                         # Cargo-installed ripgrep

# Monitor mode -- observe what would be blocked without enforcing
can run --monitor --recipe my_policy.toml -- ./my_program

# Verbose logging (debug level)
can -v run -- ls /
```

### Inspect seccomp baseline

```
$ can recipes
Discovered recipes:

  elixir               Elixir/Erlang (BEAM VM) — mix, iex, Phoenix
                       +ptrace                        recipes/elixir.toml
  ...

Default baseline: ~130 allowed, ~16 denied syscalls
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
   Essential system paths (`/bin`, `/lib`, `/usr`, `/proc`) and whitelisted
   paths are bind-mounted read-only. For commands installed via Nix, Homebrew,
   or other package managers, the install prefix is auto-detected and mounted.
   The host filesystem is unmounted.

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

## Configuration

Canister uses TOML recipe files. All fields have sensible defaults.
Unknown fields are rejected. Recipes can include a `[recipe]` metadata
section and a `[syscalls]` section to customize the seccomp baseline.

```toml
[recipe]
name = "my-policy"
description = "Policy for my project"

[filesystem]
allow = ["/usr/lib", "/usr/bin", "/tmp/workspace"]
deny  = ["/etc/shadow"]

[network]
allow_domains = ["pypi.org", "files.pythonhosted.org"]
allow_ips     = ["10.0.0.0/8"]
deny_all      = true   # default

[process]
max_pids       = 64
allow_execve   = ["/usr/bin/python3"]
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
│   ├── can-cli/        # CLI binary (clap)
│   ├── can-sandbox/    # Core runtime: namespaces, overlay, seccomp
│   ├── can-policy/     # Config parsing, whitelist logic, profile definitions
│   ├── can-net/        # Network isolation: netns, slirp4netns, DNS proxy
│   └── can-log/        # TTY-aware structured logging
├── recipes/
│   ├── default.toml    # Default seccomp baseline (embedded + overridable)
│   ├── example.toml    # Example recipe (all options documented)
│   ├── elixir.toml     # Elixir/Erlang development recipe
│   ├── python-pip.toml # Python pip install recipe
│   ├── node-build.toml # Node.js build recipe
│   └── generic-strict.toml # Strict deny-all recipe for CI
├── docs/
│   ├── ARCHITECTURE.md # Design and execution flow
│   ├── CONFIGURATION.md# Complete config reference
│   └── SECCOMP.md      # Seccomp baseline and filtering docs
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
