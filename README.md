<p align="center">
  <strong>canister</strong><br>
  <em>A lightweight sandbox for running untrusted code safely on Linux.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#configuration">Configuration</a> &middot;
  <a href="docs/ARCHITECTURE.md">Architecture</a> &middot;
  <a href="docs/CONFIGURATION.md">Config Reference</a> &middot;
  <a href="docs/PROFILES.md">Seccomp Profiles</a>
</p>

---

**Canister** (`can`) runs any command inside an isolated sandbox with restricted
filesystem, network, and syscall access. No root required. Single binary, zero
runtime dependencies.

```
$ can run --config profiles/example.toml -- python3 untrusted_script.py
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
- **Seccomp BPF** -- deny-list syscall filtering with built-in profiles for generic, Python, Node.js, and Elixir/Erlang workloads
- **Process isolation** -- PID namespace, environment filtering, RLIMIT_NPROC, execve whitelisting
- **Monitor mode** -- run with `--monitor` to observe what would be blocked without enforcing, then iterate on your policy
- **Single binary** -- pure Rust, no external library dependencies
- **Graceful degradation** -- detects AppArmor restrictions and falls back to reduced isolation with clear warnings
- **TOML config** -- strict schema with `deny_unknown_fields`, sensible defaults
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
# Minimal -- default deny-all policy, generic seccomp profile
can run -- echo "hello from the sandbox"

# With a config file
can run --config profiles/example.toml -- python3 script.py

# Elixir/Erlang -- run mix tasks or iex
can run --config profiles/elixir.toml -- mix test
can run --config profiles/elixir.toml -- iex -S mix

# Commands from any package manager work automatically:
# Nix, Homebrew, Cargo, pipx, etc. -- prefix is auto-detected and mounted
can run -- iex -e 'IO.puts("hello")'        # Nix-installed Elixir
can run -- rg --help                         # Cargo-installed ripgrep

# Override the seccomp profile
can run --profile python -- python3 -c "print('safe')"

# Monitor mode -- observe what would be blocked without enforcing
can run --monitor --config my_policy.toml -- ./my_program

# Verbose logging (debug level)
can -v run -- ls /
```

### Inspect seccomp profiles

```
$ can profiles
Available seccomp profiles:

  generic      Generic profile for arbitrary binaries. (16 denied syscalls)
  python       Profile for Python scripts. (22 denied syscalls)
  node         Profile for Node.js scripts. (22 denied syscalls)
  elixir       Profile for Elixir/Erlang (BEAM VM). (21 denied syscalls)
```

## How It Works

Canister combines five Linux isolation mechanisms:

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
   `exec`. It validates the CPU architecture (prevents x32 ABI bypass) and
   returns `EPERM` for denied syscalls. The process survives and can handle
   the error gracefully.

For a detailed walkthrough, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Configuration

Canister uses TOML configuration files. All fields have sensible defaults.
Unknown fields are rejected.

```toml
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

[profile]
name = "python"   # or "generic", "node", "elixir"
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
| Seccomp BPF | Syscall access | Filter bypass (architecture-validated) |
| PID namespace | Process visibility | Namespace escape (blocked by seccomp) |
| Environment filtering | Host env leakage | N/A (applied at exec) |
| RLIMIT_NPROC | Fork bombs | Kernel exploit |
| Read-only bind mounts | Write access | Remount (blocked by seccomp) |

**What Canister does NOT protect against:**

- Kernel exploits (no sandbox can)
- Side-channel attacks (timing, cache)
- Resource exhaustion (cgroups limits are planned but not yet enforced)
- Attacks within the allowed surface (if you whitelist `/`, there's no filesystem isolation)

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
├── profiles/
│   ├── example.toml    # Example sandbox configuration
│   └── elixir.toml     # Elixir/Erlang sandbox configuration
├── docs/
│   ├── ARCHITECTURE.md # Design and execution flow
│   ├── CONFIGURATION.md# Complete config reference
│   └── PROFILES.md     # Seccomp profile documentation
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

## Roadmap

- [x] Phase 1: Namespace core + CLI skeleton
- [x] Phase 2: Filesystem isolation (overlay + pivot_root)
- [x] Phase 3: Network isolation (slirp4netns + DNS proxy)
- [x] Phase 4: Seccomp BPF profiles
- [x] Phase 5: Process control + environment filtering
- [x] Phase 6: Monitor mode + Elixir/Erlang profile
- [x] Phase 6b: Package manager support (Nix, Homebrew, Guix, Snap, etc.)
- [ ] Phase 7: Resource limits (cgroups v2)
- [ ] Phase 8: Testing, docs, release

## License

MIT OR Apache-2.0
