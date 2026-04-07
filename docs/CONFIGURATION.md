# Configuration Reference

Canister uses TOML configuration files with strict schema validation. Unknown
fields are rejected at parse time.

When no config file is provided (`can run -- command`), a **default deny-all**
policy is used: no filesystem access, no network, generic seccomp profile.

## Table of Contents

- [filesystem](#filesystem)
  - [Auto-Mounting](#auto-mounting)
- [network](#network)
- [process](#process)
- [resources](#resources)
- [profile](#profile)
- [Monitor Mode](#monitor-mode)
- [Examples](#examples)

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
- Essential paths (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/lib`, `/lib64`,
  `/usr/lib`) are always mounted regardless of config.
- **Auto-mounting:** When the command binary lives outside standard FHS paths
  (e.g., installed via Nix, Homebrew, Guix, Snap, Cargo, or similar), Canister
  automatically detects the package-manager prefix and bind-mounts it read-only.
  A warning is logged suggesting you add the prefix to `allow` to silence it.
  See [Auto-Mounting](#auto-mounting) below.
- When filesystem isolation is degraded (AppArmor blocks mounts), these
  settings have no effect -- the process sees the full host filesystem.

```toml
[filesystem]
allow = ["/usr/lib", "/usr/bin", "/tmp/workspace", "/home/user/data"]
deny  = ["/etc/shadow", "/etc/passwd", "/root", "/home/user/.ssh"]
```

### Auto-Mounting

When the command binary is installed outside standard system paths, Canister
automatically detects and mounts the package-manager prefix so the command
can execute inside the sandbox. This works generically across package managers:

| Package manager | Example command path                     | Auto-mounted prefix  |
|-----------------|------------------------------------------|----------------------|
| Nix / NixOS     | `/nix/store/<hash>-elixir/bin/iex`       | `/nix/store`         |
| GNU Guix        | `/gnu/store/<hash>-guile/bin/guile`      | `/gnu/store`         |
| Homebrew        | `/opt/homebrew/bin/python3`              | `/opt/homebrew`      |
| Snap            | `/snap/core22/current/usr/bin/hello`     | `/snap`              |
| Flatpak         | `/var/lib/flatpak/app/.../bin/foo`       | `/var/lib/flatpak`   |
| Cargo           | `/home/user/.cargo/bin/rg`              | `/home/user/.cargo`  |
| pipx / npm      | `/home/user/.local/bin/tool`            | `/home/user/.local`  |

**How it works:**

1. The command path is **canonicalized** (all symlinks resolved) at startup.
2. The package-manager root is detected from the canonical path.
3. The entire prefix tree is bind-mounted read-only into the sandbox.
4. A warning is logged:
   ```
   WARN auto-mounting package prefix for command (add to [filesystem] allow to silence this warning)
        prefix=/nix/store command=/nix/store/abc-elixir/bin/iex
   ```

**To silence the warning**, add the detected prefix to `[filesystem] allow`:

```toml
[filesystem]
allow = ["/nix/store"]   # or /opt/homebrew, /home/user/.cargo, etc.
```

**Security note:** Auto-mounting makes the prefix *visible* inside the
sandbox but does not grant execution permission. The `[process] allow_execve`
whitelist independently controls what binaries can be executed.

**Interaction with deny:**

If the auto-detected prefix is in `[filesystem] deny`, it is **not** mounted
and the command will likely fail with ENOENT. This is intentional — deny
rules always take precedence.

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

**Limitation:** `allow_execve` only validates the *initial* command. Child
processes inside the sandbox can exec arbitrary binaries. Full ongoing
enforcement requires `SECCOMP_RET_USER_NOTIF` (planned for a future phase).

```toml
[process]
max_pids = 64
allow_execve = ["/usr/bin/python3", "/usr/bin/pip"]
env_passthrough = ["PATH", "HOME", "LANG", "TERM", "VIRTUAL_ENV"]
```

---

## `[resources]`

Resource limits via cgroups v2. **Currently parsed but not yet enforced at
runtime** (planned for Phase 7).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `memory_mb` | `int` (optional) | none | Memory limit in megabytes |
| `cpu_percent` | `int` (optional) | none | CPU limit as percentage of one core (e.g., 50 = 50%) |

```toml
[resources]
memory_mb = 512
cpu_percent = 100
```

---

## `[profile]`

Selects the seccomp BPF profile applied to the sandboxed process.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `string` | `"generic"` | Profile name: `"generic"`, `"python"`, `"node"`, or `"elixir"` |

The profile can also be overridden from the command line:

```bash
can run --profile python -- python3 script.py
```

CLI `--profile` takes precedence over the config file.

See [PROFILES.md](PROFILES.md) for details on what each profile blocks.

```toml
[profile]
name = "python"
```

---

## Monitor Mode

Monitor mode (`--monitor`) is a CLI flag, not a config field. It relaxes
enforcement across all policy sections so you can observe what would be
blocked without actually blocking it.

```bash
can run --monitor --config my_policy.toml -- python3 script.py
```

**What changes in monitor mode:**

| Section | Normal | Monitor |
|---------|--------|---------|
| `[process].allow_execve` | Blocks unlisted commands | Logs warning, allows |
| `[process].env_passthrough` | Strips unlisted vars | Logs stripped count, passes all |
| `[process].max_pids` | Enforces RLIMIT_NPROC | Logs limit, skips enforcement |
| `[profile]` seccomp | Returns EPERM on denied syscalls | Logs to kernel audit, allows |
| `[filesystem]` | Overlay + pivot_root | Unchanged (isolation active) |
| `[network]` | Namespace + slirp4netns | Unchanged (isolation active) |

**Reading monitor output:**

- Look for `MONITOR:` prefixed log lines in stderr.
- Seccomp events appear in kernel logs: `journalctl -k | grep seccomp`.
- A pre-run policy preview and post-run summary are printed automatically.

Monitor mode is a development tool. It provides **no security guarantees**.

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
[profile]
name = "generic"
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

[profile]
name = "python"
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

[profile]
name = "node"
```

### Full network trust

For trusted code that needs unrestricted network access but should still be
filesystem- and syscall-restricted.

```toml
[filesystem]
allow = ["/tmp/workspace"]

[network]
deny_all = false

[profile]
name = "generic"
```

### Air-gapped

No network, no filesystem beyond essentials, strict seccomp.

```toml
[filesystem]
allow = ["/tmp/workspace"]
deny  = ["/etc", "/root", "/home"]

[network]
deny_all = true

[profile]
name = "python"
```

### Elixir/Erlang (mix tasks, iex, Phoenix)

Run mix tasks, iex shells, or Phoenix servers with hex.pm access.

```toml
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

[profile]
name = "elixir"
```

Usage:

```bash
can run --config elixir.toml -- mix test
can run --config elixir.toml -- iex -S mix
can run --config elixir.toml -- mix phx.server
```
