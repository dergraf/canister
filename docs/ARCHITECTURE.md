# Architecture

This document describes the internal design of Canister, the execution flow
of a sandboxed process, and the security properties of each isolation layer.

## Table of Contents

- [Design Principles](#design-principles)
- [Crate Structure](#crate-structure)
- [Execution Flow](#execution-flow)
- [Isolation Layers](#isolation-layers)
  - [User Namespaces](#1-user-namespaces)
  - [Mount Namespace + pivot_root](#2-mount-namespace--pivot_root)
  - [Network Namespace](#3-network-namespace)
  - [Seccomp BPF](#4-seccomp-bpf)
  - [Seccomp USER_NOTIF Supervisor](#4b-seccomp-user_notif-supervisor)
  - [Process Control](#5-process-control)
  - [Cgroups v2](#6-cgroups-v2)
  - [/proc Hardening](#7-proc-hardening)
  - [Capability Dropping](#8-capability-dropping)
  - [Default Resource Limits](#9-default-resource-limits)
  - [Monitor Mode](#10-monitor-mode)
  - [Strict Mode](#11-strict-mode)
- [Parent-Child Protocol](#parent-child-protocol)
- [Mandatory Access Control (MAC)](#mandatory-access-control-mac)
- [Known Limitations](#known-limitations)

---

## Design Principles

1. **Unprivileged by default.** No root, no suid, no capabilities. Everything
   runs as the calling user using unprivileged user namespaces.

2. **Defense in depth.** Multiple independent isolation mechanisms. Bypassing one
   layer does not compromise the others.

3. **Fail closed.** When a feature cannot be set up (e.g., a MAC system blocks
   mounts), Canister aborts. All setup failures are fatal in both normal and
   strict mode — the sandbox runs at full strength or not at all.

4. **Single binary.** No runtime dependencies beyond the Linux kernel (and
   optionally pasta for filtered networking). No dynamic linking to
   external libraries.

5. **One-shot execution.** Fork, isolate, exec, wait, exit. No daemon, no
   long-running supervisor process. The sandbox lifetime equals the command
   lifetime.

---

## Crate Structure

```
canister/
├── can-cli        CLI binary. Argument parsing (clap), recipe
│                  resolution (name-based lookup, auto-detection
│                  via match_prefix), composition chain assembly,
│                  `can up` (manifest-driven sandboxes from
│                  canister.toml), `can recipe show` (emit resolved
│                  policy as TOML), can init / can update lifecycle
│                  commands.
│
├── can-sandbox    Core runtime. Orchestrates the fork/unshare/exec
│                  sequence. Contains the namespace, overlay, and
│                  seccomp modules.
│
├── can-policy     Policy engine. TOML config parsing, RecipeFile
│                  merge logic, environment variable expansion
│                  ($HOME, $USER, etc.), access control enforcement
│                  (path, domain, IP/CIDR), seccomp profile
│                  definitions. Also contains the project manifest
│                  module (manifest.rs) for canister.toml parsing,
│                  validation, and upward directory discovery.
│                  No Linux-specific code.
│
├── can-net        Network isolation. Network namespace setup,
│                  loopback interface, pasta integration,
│                  DNS proxy with domain filtering.
│
└── can-log        Logging setup. TTY detection, human vs JSON
                   output selection, monitor-mode event types
                   and summary output.
```

Dependencies flow downward: `can-cli` -> `can-sandbox` -> `can-policy`,
`can-net`. `can-policy` and `can-log` have no internal dependencies.

---

## Execution Flow

Canister supports two entry points:

- **`can run -r ... -- command`** — ad-hoc sandboxing with explicit recipe flags
- **`can up [name]`** — manifest-driven sandboxing from `canister.toml`

Both converge on the same fork/unshare/exec pipeline. The only difference
is how the recipe chain is assembled in step 1.

### Manifest Discovery (`can up`)

When `can up` is invoked, the CLI discovers `canister.toml` by walking up
from the current directory (like `.gitignore`). It parses the manifest,
resolves the named sandbox (or the first defined sandbox alphabetically),
and assembles the recipe chain from the manifest's `recipes = [...]` list
plus any `[sandbox.<name>.filesystem]` / `[sandbox.<name>.network]` / etc.
overrides.

**Composition order for `can up`:**

```
base.toml
  → auto-detected recipes (match_prefix against command binary)
  → recipes listed in manifest (left to right)
  → manifest overrides ([sandbox.<name>.filesystem], etc.)
  = final SandboxConfig
```

This replaces the explicit `--recipe` flags from `can run` with the
manifest's declarative recipe list. The resolved `SandboxConfig` is
identical in structure and is passed to the same sandbox runtime.

### `can run` Flow

The complete lifecycle of `can run -r nix -r elixir -- mix test`:

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. CLI SETUP                                                        │
│    a. Parse args, resolve + canonicalize command path               │
│    b. Load base.toml (embedded, overridable)                        │
│    c. Auto-detect recipes: match resolved binary path against       │
│       match_prefix in all discovered recipe files                   │
│    d. Load explicit --recipe args (name-based lookup or file path)  │
│    e. Merge recipe chain: base → auto-detected → explicit (L-to-R) │
│    f. Expand env vars ($HOME, $USER, etc.) in merged config         │
│    g. Validate allow_execve, determine network mode                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────────┐
│ 1b. NOTIFIER SETUP (before fork)                                     │
│    a. Resolve notifier_enabled (config override / monitor mode /    │
│       kernel version auto-detect)                                   │
│    b. If enabled: create anonymous Unix socket pair for fd passing  │
│       (parent_sock, child_sock)                                     │
│    c. Pre-resolve allowed domains to IPs (already done in network   │
│       setup — IPs stored for building notifier policy)              │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────────┐
│ 2. FORK                                                             │
│    Create three pipes (child_ready, maps_done, network_done).   │
│    Capture UID/GID. Call fork().                                │
└──────────┬──────────────────────────────────────┬───────────────────┘
           │                                      │
    ┌──────▼──────┐                        ┌──────▼──────┐
    │   PARENT    │                        │    CHILD    │
    │             │                        │             │
    │             │                        │ 3. UNSHARE  │
    │             │                        │    Phase 1: │
    │             │                        │    USER+PID │
    │             │                        │    [+NET]   │
    │             │    "ready" ◄────────── │             │
    │             │                        │             │
    │ 4. UID/GID  │                        │   (blocks   │
    │    MAPPING   │                        │   maps_done)│
    │    Write     │                        │             │
    │    /proc/    │                        │             │
    │    <pid>/    │                        │             │
    │    uid_map   │                        │             │
    │    gid_map   │                        │             │
    │             │ ──► "maps_done"        │             │
    │             │                        │   (blocks   │
    │ 5. NETWORK  │                        │   net_done) │
    │    Start    │                        │             │
    │    pasta    │                        │             │
    │    --userns │                        │             │
    │    --netns  │                        │             │
    │             │ ──► "net_done"         │             │
    │             │                        │             │
    │             │                        │ 5b.UNSHARE  │
    │             │                        │    Phase 2: │
    │             │                        │    NEWNS    │
    │             │                        │             │
     │             │                        │ 6. PID NS   │
     │             │                        │    First    │
     │             │                        │    fork()   │
     │             │                        │    (creates │
     │             │                        │    new PID  │
     │             │                        │    ns)      │
     │             │                        │             │
     │             │                        │    Interme- │
     │             │                        │    diate:   │
     │             │                        │    waitpid  │
     │             │                        │    + exit   │
     │             │                        │             │
     │             │                        │ 6a. SECOND  │
     │             │                        │    FORK     │
     │             │                        │    (when    │
     │             │                        │    notifier │
     │             │                        │    enabled) │
     │             │                        │             │
     │             │                        │   ┌─ PID 1: │
     │             │                        │   │  SUPER- │
     │             │                        │   │  VISOR  │
     │             │                        │   │  unshare│
     │             │                        │   │  NEWNS  │
     │             │                        │   │  mount  │
     │             │                        │   │  /proc  │
     │             │                        │   │  recv   │
     │             │                        │   │  notif  │
     │             │                        │   │  fd via │
     │             │                        │   │  SCM_   │
     │             │                        │   │  RIGHTS │
     │             │                        │   │  poll + │
     │             │                        │   │  waitpid│
     │             │                        │   │  loop   │
     │             │                        │   │         │
     │             │                        │   └─ PID 2: │
     │             │                        │      WORKER │
     │             │                        │      setsid │
    │             │                        │             │
    │             │                        │ 6b. CGROUP  │
    │             │                        │    Create   │
    │             │                        │    child    │
    │             │                        │    cgroup,  │
    │             │                        │    write    │
    │             │                        │    memory   │
    │             │                        │    .max +   │
    │             │                        │    cpu.max  │
    │             │                        │    (before  │
    │             │                        │    pivot_   │
    │             │                        │    root)    │
    │             │                        │             │
    │             │                        │ 7. OVERLAY  │
    │             │                        │    tmpfs    │
    │             │                        │    root,    │
    │             │                        │    bind     │
    │             │                        │    mounts   │
    │             │                        │    (from    │
    │             │                        │    merged   │
    │             │                        │    config), │
    │             │                        │    CWD bind │
    │             │                        │    mount    │
    │             │                        │    (RW),    │
    │             │                        │    pivot_   │
    │             │                        │    root,    │
    │             │                        │    chdir()  │
    │             │                        │             │
    │             │                        │ 7b. PROC    │
    │             │                        │    HARDEN   │
    │             │                        │    Mask     │
    │             │                        │    /proc/*  │
    │             │                        │             │
    │             │                        │ 8. NET      │
    │             │                        │    SETUP    │
    │             │                        │    loopback │
    │             │                        │    resolv.  │
    │             │                        │    conf     │
    │             │                        │             │
    │             │                        │ 9. PROCESS  │
    │             │                        │    RLIMIT   │
    │             │                        │    NPROC    │
    │             │                        │             │
     │             │                        │ 10. NOTIF   │
     │             │                        │    FILTER   │
     │             │                        │    Worker   │
     │             │                        │    installs │
     │             │                        │    USER_    │
     │             │                        │    NOTIF    │
     │             │                        │    BPF,     │
     │             │                        │    sends fd │
     │             │                        │    to PID 1 │
     │             │                        │    (super-  │
     │             │                        │    visor)   │
     │             │                        │    via SCM_ │
     │             │                        │    RIGHTS   │
     │             │                        │             │
     │             │                        │ 11. SECCOMP │
    │             │                        │    Load     │
    │             │                        │    main BPF │
    │             │                        │    filter   │
    │             │                        │             │
    │             │                        │ 12. ENV     │
    │             │                        │    Filter   │
    │             │                        │    env vars │
    │             │                        │             │
    │             │                        │ 13. EXEC    │
    │             │                        │    execve() │
    │             │                        │             │
    │ 14. WAIT   │                        │  (running)  │
    │     waitpid │                        │             │
    │             │                        │ (exits)     │
    │             │                        └─────────────┘
     │ 15. CLEANUP│
     │    Kill     │
     │    pasta    │
     │    Stop DNS │
     │    proxy    │
     │    Return   │
     │    exit code│
     └─────────────┘
```

**Critical ordering constraints:**

- Recipe composition (load, merge, env expansion) happens entirely in the
  CLI layer **before** forking. The child receives an already-resolved
  `SandboxConfig`.
- `unshare()` is split into two phases. Phase 1: `unshare(CLONE_NEWUSER |
  CLONE_NEWPID | CLONE_NEWNET)` — creates user, PID, and network namespaces.
  Phase 2: `unshare(CLONE_NEWNS)` — creates the mount namespace. The split
  is necessary so pasta can access `/proc/<child_pid>/ns/net` before the
  child's mount namespace changes.
- UID/GID maps must be written from the **parent** process. The child cannot
  write its own maps after `unshare(CLONE_NEWUSER)`.
- pasta must be started after the child creates `CLONE_NEWNET` and after
  UID/GID maps are written, but before the child calls `unshare(CLONE_NEWNS)`.
  pasta is invoked with `--userns /proc/<child_pid>/ns/user --netns /proc/<child_pid>/ns/net --runas <uid>`.
- The inner fork for PID namespace must happen before filesystem setup so
  `/proc` mount reflects the new PID namespace.
- `setsid()` must be called after the inner PID namespace fork. PID 1
  inherits an invisible session/process-group from the parent namespace;
  without `setsid()`, bash's job control initialization fails (`getpgrp`
  returns the parent-namespace group).
- /proc hardening must happen after overlay + /proc mount but before seccomp.
- `RLIMIT_NPROC` must be set before seccomp (which blocks `prctl`).
- Cgroups v2 setup must happen **before** `pivot_root`, because the cgroup
  filesystem (`/sys/fs/cgroup`) is on the host and becomes inaccessible after
  the root is swapped. This is step 6b in the execution flow.
- The CWD bind-mount must happen during overlay setup (step 7), before
  `pivot_root`. The host's current working directory is captured before
  `unshare()` and bind-mounted writable into the new root. After
  `pivot_root`, the child calls `chdir()` to the mounted CWD path.
- The notifier filter must be installed **before** the main seccomp filter.
  The `seccomp()` syscall with `SECCOMP_FILTER_FLAG_NEW_LISTENER` returns
  the notification fd. The worker (PID 2) sends this fd to PID 1 (supervisor)
  via SCM_RIGHTS, then installs the main filter via `prctl(PR_SET_SECCOMP)`.
- PID 1 (the supervisor) must receive the notifier fd and begin its poll loop
  before the worker calls `execve()`, so the supervisor is ready to handle
  notifications from the target program.
- Seccomp must be loaded **after** all setup is complete, right before exec.
- Environment filtering happens at exec time — `execve()` receives the
  filtered environment directly.

---

## Isolation Layers

### 1. User Namespaces

**Syscall:** `unshare(CLONE_NEWUSER)`

The child process gets a new user namespace where it is mapped as UID 0 / GID 0.
This gives it "root inside the namespace" which is required for mount
operations, but grants **zero real privileges** on the host.

The parent writes the mapping:

```
/proc/<pid>/setgroups → "deny"
/proc/<pid>/uid_map   → "0 <host_uid> 1"
/proc/<pid>/gid_map   → "0 <host_gid> 1"
```

**Security property:** The child appears to be root but cannot affect any
resources outside its namespace. All privilege checks are scoped to the
namespace.

### 2. Mount Namespace + pivot_root

**Syscall:** `unshare(CLONE_NEWNS)` + `pivot_root()`

The child gets its own mount table. The setup sequence:

```
1.  mount("", "/", MS_SLAVE | MS_REC)     # break propagation to host
2.  mount("tmpfs", new_root)               # empty tmpfs as new root
3.  mkdir skeleton dirs                     # /bin, /lib, /usr, /proc, /dev, /tmp, ...
4.  bind-mount essentials (read-only)       # from base.toml: /bin, /sbin, /usr/bin, ...
5.  bind-mount allowed paths (RO)           # from merged [filesystem].allow (all recipes)
5b. bind-mount CWD (read-write)            # host working directory, always mounted
6.  mount /tmp (read-write)                 # ephemeral writable space
7.  mount /proc                             # needed by many programs
8.  set up /dev                             # null, zero, urandom, tty, fd symlinks
9.  pivot_root(new_root, old_root)          # swap filesystem root
10. umount(old_root, MNT_DETACH)           # detach host filesystem entirely
11. chdir(cwd_path)                         # restore working directory inside new root
```

**Recipe-based mount resolution:**

The paths visible inside the sandbox come from the merged recipe chain
(`base.toml` → auto-detected → explicit). There is no hardcoded prefix
detection at runtime. Instead:

1. **`base.toml`** defines essential OS bind mounts (`/bin`, `/sbin`,
   `/usr/bin`, `/usr/sbin`, `/lib`, `/lib64`, `/usr/lib`, `/etc`). It is
   embedded in the binary via `include_str!()` and overridable on disk,
   following the same pattern as `default.toml`.

2. **Auto-detected recipes** provide package-manager mounts. Each recipe
   declares `match_prefix` patterns in its `[recipe]` metadata. During CLI
   setup (before fork), the resolved binary path is matched against all
   discovered recipes. Matching recipes are merged into the chain, bringing
   their `[filesystem].allow` paths with them:

   | Recipe | `match_prefix` | Adds to `allow` |
   |--------|---------------|-----------------|
   | `nix.toml` | `/nix/store` | `/nix/store` |
   | `homebrew.toml` | `/opt/homebrew`, `/home/linuxbrew/.linuxbrew` | `/opt/homebrew` (or linuxbrew) |
   | `cargo.toml` | `$HOME/.cargo`, `$HOME/.rustup` | `$HOME/.cargo`, `$HOME/.rustup` |
   | `snap.toml` | `/snap` | `/snap` |
   | `flatpak.toml` | `/var/lib/flatpak`, `$HOME/.local/share/flatpak` | prefix paths |
   | `gnu-store.toml` | `/gnu/store` | `/gnu/store` |

3. **Explicit recipes** (`--recipe` / `-r` flags) add whatever
   `[filesystem].allow` paths they declare.

4. **Environment variable expansion** (`$HOME`, `$USER`, `${XDG_CONFIG_HOME}`)
   is performed during `into_sandbox_config()`, after merge but before the
   paths are used by the overlay module.

This design means adding support for a new package manager is "write a
`.toml` file" rather than "modify Rust code". The `detect_command_prefix()`
function was removed entirely.

**Security model:** Filesystem visibility does not equal execution permission.
Mounted paths are visible inside the sandbox, but `allow_execve` and the
USER_NOTIF supervisor's `execve()`/`execveat()` filtering control what can
actually be *executed*.

**Security property:** The process cannot see or access any host path that
was not explicitly included in the merged recipe chain. The host's current
working directory is always bind-mounted writable so the sandboxed process
can read/write files in its working directory. All other writes go to tmpfs
and are discarded when the process exits.

**MAC systems:** When a Mandatory Access Control system (AppArmor on Ubuntu,
SELinux on Fedora/RHEL) blocks mount operations, filesystem isolation cannot be
established and the sandbox aborts. Run `sudo can setup` to install the
appropriate security policy (see [MAC section](#mandatory-access-control-mac)).

### 3. Network Namespace

**Syscall:** `unshare(CLONE_NEWNET)` + pasta

Three modes, determined from config:

**None mode:** The sandbox has an empty network namespace with only loopback.
No external connectivity.

**Filtered mode:** The parent starts `pasta` which mirrors the host's
network configuration into the child's network namespace. pasta copies the
host's real IP addresses, routes, and gateway into the namespace:

```
┌──────────────────────────────────┐
│         Host network             │
│                                  │
│   pasta ◄──── namespace fd       │
│       │                          │
│       │  mirrors host config     │
│       │                          │
└───────┼──────────────────────────┘
        │
┌───────┼──────────────────────────┐
│       ▼      Sandbox network     │
│   Host's real IP (mirrored)      │
│   gateway: host's default gw     │
│   DNS: 169.254.0.1 (link-local)  │
│                                  │
│   ┌─────────────────────────┐    │
│   │   sandboxed process     │    │
│   └─────────────────────────┘    │
└──────────────────────────────────┘
```

Allowed domains are pre-resolved to IP addresses at startup (from the
parent, which still has host DNS access). These resolved IPs are passed to
the USER_NOTIF supervisor, which intercepts `connect()` syscalls and validates
the destination IP against the allow list. A DNS proxy runs in the **parent
process** on an ephemeral port, filtering DNS queries to only resolve
allowed domains. The sandbox's `/etc/resolv.conf` is configured to use
pasta's DNS address (`169.254.0.1:53`, set via `--dns`), which routes
queries to the parent's DNS proxy via `--dns-forward`. This prevents
DNS-based information exfiltration.

**Port forwarding:** When `-p` / `--port` flags are specified, pasta is
configured with explicit port forwarding rules via `-t` (TCP) and `-u`
(UDP) options. Auto-forwarding is disabled (`-t none -u none`) and only
the specified ports are forwarded.

**Full mode:** No `CLONE_NEWNET`. The sandbox shares the host network.

**Security property:** In None mode, the process has zero network access.
In Filtered mode, connectivity is routed through pasta, and the
USER_NOTIF supervisor enforces IP-level connect() filtering against the
allowed domain/IP list. DNS queries are restricted to allowed
domains. In Full mode, there is no network isolation.

### 4. Seccomp BPF

**Syscall:** `prctl(PR_SET_NO_NEW_PRIVS)` + `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`

A classic BPF program is loaded right before `execve()`. The filter is
generated at runtime from the default baseline defined in
`recipes/default.toml` (~187 allowed, ~18 always-denied) plus any
`[syscalls]` overrides (`allow_extra` / `deny_extra`).

When the USER_NOTIF supervisor is enabled, two BPF filters are installed:

1. **Notifier filter** (installed first, via `seccomp()` with
   `SECCOMP_FILTER_FLAG_NEW_LISTENER`): Returns `SECCOMP_RET_USER_NOTIF` for
   eight intercepted syscalls (`connect`, `sendto`, `sendmsg`, `clone`, `clone3`,
   `socket`, `execve`, `execveat`). All others return `SECCOMP_RET_ALLOW`.

2. **Main filter** (installed second, via `prctl(PR_SET_SECCOMP)`): The
   standard allow-list or deny-list filter described below.

The kernel evaluates filters in reverse install order, but
`SECCOMP_RET_USER_NOTIF` takes special precedence — when present, the kernel
always delivers the notification to the supervisor. See
[Seccomp USER_NOTIF Supervisor](#4b-seccomp-user_notif-supervisor) for details.

When the notifier is disabled (kernel < 5.9, monitor mode, or `notifier = false`),
only the main filter is installed.

The baseline is embedded in the binary via `include_str!()` so it works
standalone. At runtime, Canister searches for an external `default.toml` in
`./.canister/`, `$XDG_CONFIG_HOME/canister/recipes/`, and
`/etc/canister/recipes/`. If found, the external file takes precedence over
the embedded copy. This lets users pin, audit, or version-control the
baseline without recompiling.

**Two modes — allow-list (default) and deny-list:**

| Mode | Default action | Listed syscalls | Recommended for |
|------|---------------|-----------------|-----------------|
| **Allow-list** (default) | DENY | Permitted | Production, CI |
| **Deny-list** | ALLOW | Blocked | Compatibility, unknown workloads |

Allow-list mode is the default and recommended mode. It inverts the
security model: only syscalls explicitly listed in the profile are
permitted; everything else is denied. This provides a much smaller attack
surface than a deny-list.

**BPF program structure (allow-list mode):**

```
Instruction  What it does
─────────────────────────────────────────────────
[0]          Load seccomp_data.arch
[1]          If arch == x86_64: skip to [3]
[2]          Return KILL_PROCESS (wrong architecture)
[3]          Load seccomp_data.nr (syscall number)
[4]          If nr == allowed_0: jump to [ALLOW]
[5]          If nr == allowed_1: jump to [ALLOW]
...
[N]          If nr == allowed_K: jump to [ALLOW]
[N+1]        Return ERRNO(EPERM) (no match → denied)
[N+2]        Return ALLOW (match → permitted)
```

**BPF program structure (deny-list mode):**

```
Instruction  What it does
─────────────────────────────────────────────────
[0]          Load seccomp_data.arch
[1]          If arch == x86_64: skip to [3]
[2]          Return KILL_PROCESS (wrong architecture)
[3]          Load seccomp_data.nr (syscall number)
[4]          If nr == denied_0: jump to [DENY]
[5]          If nr == denied_1: jump to [DENY]
...
[N]          If nr == denied_K: jump to [DENY]
[N+1]        Return ALLOW (no match → permitted)
[N+2]        Return ERRNO(EPERM) (match → denied)
```

The mode is selected via `[syscalls] seccomp_mode` in the config file
(default: `"allow-list"`).

**Architecture validation:** The first check rejects any syscall from a
non-native architecture. On x86_64, this prevents bypass via the x32 ABI
(which shares the kernel but uses different syscall numbers).

**Deny action:** In normal mode, Canister uses `SECCOMP_RET_ERRNO | EPERM`
which allows the sandboxed process to handle denied syscalls gracefully. In
**strict mode** (`--strict`), it uses `SECCOMP_RET_KILL_PROCESS` — the
process is killed immediately on any denied syscall.

**Security property:** Even if a process escapes all namespace isolation,
it cannot invoke unlisted syscalls. The filter is enforced by the kernel and
cannot be removed or modified by the filtered process (loading new seccomp
filters is blocked by the default baseline's deny list).

### 4b. Seccomp USER_NOTIF Supervisor

**Syscall:** `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)`
**Module:** `notifier.rs`

The USER_NOTIF supervisor extends seccomp BPF with argument-level inspection.
Classic BPF can only check the syscall number and architecture — it cannot
dereference pointers or read memory. The supervisor intercepts specific
syscalls via `SECCOMP_RET_USER_NOTIF`, reads the actual argument data from
`/proc/<pid>/mem`, and makes a policy decision.

**Architecture:**

The supervisor runs as **PID 1** inside the sandbox's PID namespace. This is
necessary because:

1. After `unshare(CLONE_NEWPID)`, `clone(CLONE_THREAD)` fails with `EINVAL`,
   so a supervisor thread cannot be spawned.
2. The host's procfs denies `/proc/<pid>/mem` opens from a child user namespace.
   PID 1 mounts its own procfs (owned by the sandbox's user namespace).
3. As PID 1, the supervisor is an ancestor of all sandboxed processes, satisfying
   Yama `ptrace_scope=1` without `PR_SET_PTRACER`.

```
  PID 1 (supervisor)                     PID 2+ (worker / sandboxed)
  ──────────────────                     ──────────────────────────
  unshare(CLONE_NEWNS)                   Sandbox setup (overlay, pivot_root)
  mount /proc                            seccomp() → notifier fd
  recv_fd() via SCM_RIGHTS               send_fd() via SCM_RIGHTS
       │                                 install main BPF filter
       │    connect(AF_INET, ...)        execve()
       │ ──── SUSPENDED ────────────►         │
       │                               ┌──────┴──────────────┐
       │                               │  Supervisor (PID 1) │
       │                               │  1. NOTIF_RECV      │
       │                               │  2. open+read       │
       │                               │     /proc/<pid>/mem │
       │                               │  3. Check policy    │
       │                               │  4. NOTIF_ID_VALID  │
       │    ALLOW / ERRNO(EPERM)       │  5. NOTIF_SEND      │
       │ ◄──────────────────────────── └──────────────────────┘
       │
       ▼  (continues or gets EPERM)
```

The supervisor runs inline (single-threaded) using `poll()` with a 200ms timeout,
interleaved with non-blocking `waitpid` to detect when the worker exits. After the
worker exits, remaining in-flight notifications are drained before the supervisor
terminates.

**Filtered syscalls:**

| Syscall | What is inspected | Policy enforcement |
|---------|------------------|--------------------|
| `connect()` | `sockaddr` struct (IP + port) | Must match resolved `allow_domains` IPs, `allow_ips` CIDRs, or loopback |
| `sendto()` | `dest_addr` + `msg_controllen` | DNS queries on port 53 trigger supervisor-side resolution; connected sockets (NULL addr) allowed |
| `sendmsg()` | `msghdr` struct (`msg_controllen`) | Blocks any `sendmsg()` with ancillary data (`msg_controllen > 0`), preventing SCM_RIGHTS fd passing |
| `clone()` | `flags` register | Namespace flags (`CLONE_NEWNS`, `CLONE_NEWCGROUP`, `CLONE_NEWUTS`, `CLONE_NEWIPC`, `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET`) denied |
| `clone3()` | `clone_args.flags` in userspace memory | Same namespace flag check, struct read via `/proc/<pid>/mem` |
| `socket()` | `domain` + `type` + `protocol` registers | `SOCK_RAW` denied; `AF_NETLINK` restricted to `NETLINK_ROUTE` (protocol 0) only |
| `execve()` | Pathname string in userspace memory | Must match `allow_execve` paths (empty = allow all) |
| `execveat()` | Pathname + dirfd | Same as `execve()`, with dirfd resolution |

**TOCTOU mitigation:** Between reading the worker's memory and sending the verdict,
a multi-threaded sandbox process could modify the inspected memory. The supervisor
calls `ioctl(SECCOMP_IOCTL_NOTIF_ID_VALID)` after the policy check — if the
notification ID is no longer valid (thread exited or memory was remapped), the
verdict is skipped.

**Memory access:** The supervisor (PID 1) runs in the same user namespace and PID
namespace as all sandboxed processes. It mounts its own procfs (the user namespace
owns the PID namespace, so the mount succeeds). `notif.pid` in the seccomp
notification matches PIDs visible in this procfs. As PID 1, the supervisor is an
ancestor of all sandboxed processes, so Yama `ptrace_scope=1` is satisfied without
`PR_SET_PTRACER`. The supervisor does NOT have `PR_SET_NO_NEW_PRIVS` set, which
would otherwise block `/proc/<pid>/mem` access.

**Fd passing protocol:** Before `fork()`, the parent creates an anonymous
Unix socket pair (`socketpair(AF_UNIX, SOCK_STREAM)`). One end is inherited by
the worker (PID 2+), the other by the supervisor (PID 1). After the notifier
filter is installed, the worker sends the notifier fd to PID 1 as `SCM_RIGHTS`
ancillary data.

**Requirements:** Linux 5.9+ (auto-detected from `/proc/sys/kernel/osrelease`).
Disabled in monitor mode (incompatible with `SECCOMP_RET_LOG`). Configurable
via `[syscalls] notifier` in recipe config.

**Security property:** Even syscalls that pass the main BPF filter are
subject to argument-level inspection. A sandboxed process cannot connect to
unauthorized IPs, pass file descriptors via SCM_RIGHTS, create new namespaces
via clone flags, open raw sockets, open AF_NETLINK sockets beyond NETLINK_ROUTE,
or exec binaries outside the `allow_execve` list.

### 5. Process Control

**Modules:** `process.rs` (environment filtering, PID namespace, RLIMIT_NPROC,
allow_execve validation)

Process control enforces the `[process]` config section:

**PID Namespace** (`CLONE_NEWPID` + two forks):

The child calls `unshare(CLONE_NEWPID)` atomically with the other namespace
flags. Since `CLONE_NEWPID` affects children of the calling process (not the
caller itself), the child forks to enter the new PID namespace.

When the USER_NOTIF supervisor is enabled, a **second fork** inside the new
PID namespace creates the supervisor/worker split:

- **PID 1** (supervisor): Mounts its own `/proc` via `unshare(CLONE_NEWNS)`,
  receives the notifier fd from the worker via SCM_RIGHTS, and runs the
  supervisor loop inline (single-threaded poll + waitpid).
- **PID 2+** (worker): Performs sandbox setup (overlay, pivot_root, seccomp),
  installs the USER_NOTIF filter, sends the notifier fd to PID 1, then execs
  the target command.

When the notifier is disabled, there is only one fork. The child becomes
PID 1 and proceeds directly with sandbox setup and exec.

After the inner fork, `setsid()` is called to create a new session and
process group. This is necessary because PID 1 inherits an invisible
session/process-group from the parent namespace. Without `setsid()`,
bash's job control initialization fails because `getpgrp()` returns the
parent-namespace process group ID, which doesn't exist in the new PID
namespace — causing "initialize_job_control: getpgrp failed".

The intermediate parent (in the old PID namespace) waits and propagates the exit code.

```
  Outer child (after unshare)
       │
       ├── fork()  (enters new PID namespace)
       │     │
       │     ├── [notifier enabled] fork() again:
       │     │     │
       │     │     ├── PID 1: Supervisor
       │     │     │     ├── unshare(CLONE_NEWNS)
       │     │     │     ├── mount /proc
       │     │     │     ├── recv notifier fd
       │     │     │     └── poll/waitpid supervisor loop
       │     │     │
       │     │     └── PID 2: Worker
       │     │           ├── setsid()
       │     │           ├── setup overlay, network, seccomp
       │     │           ├── install notifier filter, send fd to PID 1
       │     │           └── execve()
       │     │
       │     ├── [notifier disabled] PID 1: direct setup + exec
       │     │     ├── setsid()
       │     │     ├── setup overlay, network, seccomp
       │     │     └── execve()
       │     │
       │     └── (intermediate parent waits, exits with child's code)
```

**Security property:** The sandboxed process tree is completely isolated. It
cannot see or signal host processes via /proc or kill().

**Environment Filtering** (`env_passthrough`):

Before `execve()`, the environment is reconstructed from scratch. Only
variables listed in `env_passthrough` are kept. If the list is empty, the
process starts with a completely clean environment (zero host leakage).

A minimal `PATH` is injected if not explicitly passed through, to prevent
the sandbox from being unable to find executables.

Uses `execve()` instead of `execvp()` to pass the filtered environment
explicitly.

**Security property:** Sensitive environment variables (API keys, tokens,
credentials in `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, etc.) are never
leaked to the sandbox unless explicitly listed in `env_passthrough`.

**`max_pids`** (`RLIMIT_NPROC`):

Sets `RLIMIT_NPROC` via `setrlimit()` to cap the number of processes the
sandbox can create. This is a per-UID limit — effective because the sandbox
runs as UID 0 in its own user namespace, mapped to the host user.

**Security property:** Prevents fork bombs. A process that exceeds the limit
gets `EAGAIN` from `fork()`.

**`allow_execve`** (pre-exec validation):

The resolved command path is checked against the `allow_execve` list
before forking. If the command is not in the list (and the list is non-empty),
execution is rejected immediately.

**Prefix rules:** Entries ending in `/*` match any binary under that
directory tree. For example, `/nix/store/*` allows any binary whose
resolved path starts with `/nix/store/`. The match requires a `/` boundary
to prevent false positives (e.g., `/nix/store-extra/foo` does NOT match
`/nix/store/*`). This is essential for content-addressed stores like Nix
where binary paths contain unpredictable hashes.

**Limitation:** `allow_execve` validates the *initial* command at the CLI
level. Ongoing enforcement of every `execve()` call inside the sandbox is
provided by the USER_NOTIF supervisor (see
[Seccomp USER_NOTIF Supervisor](#4b-seccomp-user_notif-supervisor)), which
intercepts `execve()` and `execveat()` syscalls and validates the pathname
against the `allow_execve` list. When the notifier is disabled (kernel
< 5.9 or `notifier = false`), only the initial command is validated.

### 6. Cgroups v2

**Files:** `cgroups.rs`

Cgroups v2 enforces resource limits (memory and CPU) without requiring root.
It leverages systemd's per-user cgroup delegation, which is available on any
modern system running systemd (Ubuntu 22.04+, Fedora 36+, etc.).

Resource limits are **opt-in** — none of the shipped base recipes include
`[resources]`. Users add `memory_mb` and/or `cpu_percent` in their own
recipes when needed.

**Setup sequence** (happens before `pivot_root`, while `/sys/fs/cgroup` is
still accessible):

1. **Detect** the current cgroup by reading `/proc/self/cgroup`.
2. **Create** a child cgroup at `<parent>/canister-<pid>`.
3. **Write** `memory.max` (bytes) and `cpu.max` (quota/period) to the child
   cgroup's control files.
4. **Move** the sandboxed process into the child cgroup by writing its PID
   to `cgroup.procs`.

**CPU limiting:** `cpu_percent = 50` translates to `cpu.max = "50000 100000"`
(50ms quota per 100ms period), effectively capping the process to 50% of
one CPU core.

**Memory limiting:** `memory_mb = 512` translates to `memory.max = 536870912`
(512 * 1024 * 1024 bytes). When exceeded, the kernel OOM-kills the process.

**Cleanup:** Child cgroups are removed when the sandboxed process exits (the
kernel removes empty cgroups automatically).

**Failure handling:** Cgroup setup failure aborts the sandbox. All setup
failures are fatal regardless of mode.

**Security property:** The sandboxed process cannot consume unbounded memory
or CPU. The limits are enforced by the kernel's cgroup controller and cannot
be modified by the sandboxed process (which has no write access to the
cgroup filesystem after seccomp is loaded).

### 7. /proc Hardening

**Files:** `overlay.rs` (mount_proc function)

After mounting `/proc` inside the sandbox, Canister masks sensitive paths
following Docker's default behavior, plus additional hardening:

**Masked files** (bind-mount `/dev/null` over them):
- `/proc/kcore` — physical memory access
- `/proc/keys` — kernel keyring contents
- `/proc/key-users` — keyring user counts (information leak)
- `/proc/sysrq-trigger` — kernel SysRq commands
- `/proc/timer_list` — timer details (information leak)
- `/proc/latency_stats` — latency statistics
- `/proc/kallsyms` — kernel symbol addresses (KASLR bypass)
- `/proc/schedstat` — scheduler statistics (information leak)

**Masked per-process files** (bind-mount `/dev/null` over them):
- `/proc/self/mountinfo` — mount topology (reveals sandbox structure)
- `/proc/1/mountinfo` — same, for PID 1

**Masked directories** (mount empty read-only tmpfs over them):
- `/proc/acpi` — ACPI interface
- `/proc/scsi` — SCSI device interface

**Read-only remount:**
- `/proc/sys` — prevents writing to sysctl tunables

**Failure handling:** Individual mask failures are logged at debug level and
are non-fatal. The sandbox continues with whatever masking succeeded.

**Security property:** The sandboxed process cannot read sensitive kernel
information from /proc, trigger SysRq commands, modify sysctl values, or
inspect the sandbox's mount topology via mountinfo.

### 8. Capability Dropping

**Module:** `namespace.rs` (`drop_capabilities()`)

After all namespace setup is complete and before `execve()`, Canister drops
all Linux capabilities from the bounding set and clears the inheritable and
ambient sets.

**Setup sequence:**

1. Read `CAP_LAST_CAP` from `/proc/sys/kernel/cap_last_cap` to discover the
   number of capabilities on the running kernel (currently 41).
2. Drop each capability from the bounding set using
   `prctl(PR_CAPBSET_DROP, cap)`.
3. Clear the inheritable capability set using `capset()`.
4. Clear the ambient capability set using
   `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)`.

**Result after exec with `NO_NEW_PRIVS`:**

```
CapEff: 0000000000000000
CapPrm: 0000000000000000
CapBnd: 0000000000000000
CapAmb: 0000000000000000
CapInh: 0000000000000000
```

**Why this matters:** Inside a user namespace, the sandboxed process has
`CAP_SYS_ADMIN` and other capabilities that allow namespace operations. While
seccomp blocks the dangerous syscalls (mount, unshare, etc.), dropping
capabilities provides defense-in-depth. Even if a seccomp bypass were found,
the empty capability set prevents privilege escalation.

**AppArmor interaction:** The `canister` AppArmor profile requires
`allow capability setpcap,` to permit `PR_CAPBSET_DROP` calls. This is
included in the shipped profile and installed via `sudo can setup`.

**Security property:** The sandboxed process executes with no capabilities
in any set. It cannot gain capabilities through any mechanism (exec of
setuid binaries is also blocked by `NO_NEW_PRIVS`).

### 9. Default Resource Limits

**Module:** `process.rs` (`apply_default_resource_limits()`)

Before `execve()`, Canister applies conservative resource limits that
provide baseline protection even when no `[resources]` section is present
in the recipe:

| Limit | Value | Purpose |
|-------|-------|---------|
| `RLIMIT_NPROC` | 4096 | Limits total processes (fork bomb defense) |
| `RLIMIT_AS` | 8 GB | Limits virtual address space |
| `RLIMIT_NOFILE` | 4096 | Limits open file descriptors |
| `RLIMIT_FSIZE` | 4 GB | Limits maximum file size |
| `RLIMIT_CORE` | 0 | Disables core dumps (prevents data leakage) |

These defaults are applied first, then any explicit limits from the recipe's
`[resources]` section override them. The `RLIMIT_NPROC` from
`[process].max_pids` takes precedence over the default if specified.

**Security property:** Fork bombs are bounded, memory-hungry processes are
capped, and core dumps cannot leak sandbox state to disk.

### 10. Monitor Mode

**Flag:** `--monitor`

Monitor mode runs the sandbox with all namespace isolation active (for accurate
observation) but relaxes policy enforcement. Each enforcement point logs what
*would* have been blocked without actually blocking it.

**Enforcement points and their monitor-mode behavior:**

| Enforcement point | Normal mode | Monitor mode |
|-------------------|-------------|--------------|
| `allow_execve` | Rejects unlisted commands | Logs warning, allows through |
| `env_passthrough` | Strips unlisted env vars | Logs what would be stripped, passes full env |
| `max_pids` | Sets `RLIMIT_NPROC` | Logs the limit, skips `setrlimit()` |
| Seccomp BPF | `SECCOMP_RET_ERRNO` (EPERM) | `SECCOMP_RET_LOG` (allowed but kernel-logged) |
| USER_NOTIF supervisor | Active (intercepts syscalls) | Disabled (incompatible with `SECCOMP_RET_LOG`) |
| Filesystem isolation | Full overlay + pivot_root | Full overlay + pivot_root (unchanged) |
| Network isolation | Namespace + pasta | Namespace + pasta (unchanged) |

**Key design decisions:**

1. **Namespaces stay active.** Monitor mode does NOT skip namespace creation.
   This ensures the process runs in the same environment it would in enforced
   mode, so observations are accurate. If namespaces were disabled, the process
   might behave differently (different PIDs, different filesystem view, etc.).

2. **`SECCOMP_RET_LOG` for syscalls.** Instead of returning EPERM, denied
   syscalls are allowed through but logged to the kernel audit subsystem.
   View these with `journalctl -k | grep seccomp`. This uses a real BPF
   filter (same structure as enforcement mode) so the observation is exact.

3. **USER_NOTIF is disabled.** The notifier supervisor is incompatible with
   monitor mode because `SECCOMP_RET_USER_NOTIF` suspends the syscall (it
   does not log-and-allow like `SECCOMP_RET_LOG`). In monitor mode, all
   syscalls pass through to the kernel with logging only.

4. **Pre-run policy preview.** Before forking, the CLI prints a summary of
   the active policy so the user knows what enforcement points will be
   observed.

5. **Post-run summary.** After the sandboxed process exits, the CLI prints
   a summary with the exit code and hints for reviewing the monitor output.

**Intended workflow:**

```bash
# 1. Run with monitor to see what the policy would block
can run --monitor --recipe my_policy.toml -- ./my_program

# 2. Review MONITOR: lines in output and seccomp audit logs
journalctl -k | grep seccomp

# 3. Adjust policy based on observations

# 4. Run with enforcement
can run --recipe my_policy.toml -- ./my_program
```

**Security property:** Monitor mode provides NO security guarantees. It is
a development/debugging tool for iterating on sandbox policies.

**Warning:** A malicious process can detect monitor mode (e.g., by
attempting a denied syscall and observing it succeeds) and behave
differently. Always validate policies with enforcement enabled.

### 11. Strict Mode

**Flag:** `--strict` (or `strict = true` in config)

Strict mode is the inverse of monitor mode: instead of relaxing
enforcement, it tightens it. Both normal and strict mode treat all setup
failures as fatal. The key difference is the seccomp deny action.

**Changes in strict mode:**

| Enforcement point | Normal mode | Strict mode |
|-------------------|-------------|-------------|
| Filesystem isolation | **Aborts** on failure | **Aborts** on failure |
| Network setup | **Aborts** on failure | **Aborts** on failure |
| Loopback bring-up | **Aborts** on failure | **Aborts** on failure |
| Seccomp deny action | `SECCOMP_RET_ERRNO` (EPERM) | `SECCOMP_RET_KILL_PROCESS` |
| Cgroup setup | **Aborts** on failure | **Aborts** on failure |

**Mutual exclusion:** `--strict` and `--monitor` cannot be used together.
This is enforced at the CLI level.

**Recommended for:** CI pipelines, production deployments, and any
environment where reduced isolation is worse than no execution.

---

## Parent-Child Protocol

The parent and child synchronize via three anonymous pipes:

```
Pipe 1: child_ready  (child → parent)   "namespaces created"
Pipe 2: maps_done    (parent → child)   "UID/GID maps written"
Pipe 3: network_done (parent → child)   "pasta started, network ready"

Timeline:
  Child: unshare(USER+PID+NET)
  Child: write(child_ready, 0x00)       ← "namespaces created"
  Child: read(maps_done)                ← blocks

  Parent: read(child_ready)             ← unblocks
  Parent: write uid_map, gid_map
  Parent: write(maps_done, 0x00)        ← "maps written"

  Child: read(maps_done)                ← unblocks
  Child: read(network_done)             ← blocks

  Parent: start pasta --userns /proc/<child>/ns/user --netns /proc/<child>/ns/net --runas <uid>
  Parent: write(network_done, 0x00)     ← "network ready"

  Child: read(network_done)             ← unblocks
  Child: unshare(NEWNS)
  Child: install notifier filter, send fd to PID 1 supervisor (if enabled)
  Child: setup overlay, network, seccomp
  Child: execve()

  PID 1: receive notifier fd, run inline supervisor loop (if enabled)
```

This three-pipe protocol is necessary because:

1. **UID/GID maps must be written from outside the namespace.** The kernel
   requires an external process to write `/proc/<pid>/uid_map`.

2. **pasta needs the child's user and network namespaces.** pasta is invoked
   with `--userns /proc/<child_pid>/ns/user --netns /proc/<child_pid>/ns/net
   --runas <uid>`. The `setns(CLONE_NEWNET)` syscall requires `CAP_SYS_ADMIN`
   in the **user namespace that owns** the target network namespace — not the
   caller's user namespace. Since the child created both namespaces atomically
   via `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, the network namespace is owned
   by the child's user namespace. pasta must therefore first join the child's
   user namespace (`setns(CLONE_NEWUSER)`) to acquire `CAP_SYS_ADMIN` there,
   then join the network namespace (`setns(CLONE_NEWNET)`). The child calls
   `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` before signaling the parent,
   so that pasta (a sibling process) can open `/proc/<child>/ns/*` despite
   Yama `ptrace_scope=1`. `--runas <uid>` prevents pasta from dropping to
   "nobody", which would fail the kernel's UID ownership check on namespace
   files. This must happen after the child creates `CLONE_NEWNET` but before
   the child tries to use the network.

3. **Mount namespace is split from the initial unshare.** The child first
   calls `unshare(USER+PID+NET)`, then waits for pasta, then calls
   `unshare(NEWNS)` separately. This split ensures pasta can access
   `/proc/<child_pid>/ns/net` before the child's mount namespace changes.

4. **Mount operations need mapped UIDs.** The child cannot mount anything
   until its UID is mapped (otherwise the kernel rejects it).

5. **The notifier fd must be passed from worker to supervisor.** The `seccomp()`
   syscall returns the notifier fd in the worker's process. The fd is sent to
   PID 1 (supervisor) via `SCM_RIGHTS` over an anonymous Unix socket pair
   created before the supervisor/worker fork.

---

## Mandatory Access Control (MAC)

Linux distributions use Mandatory Access Control systems to restrict
unprivileged processes. Canister detects the active MAC system at runtime and
manages the appropriate security policy via `can setup`. See ADR-0004 for the
design rationale.

### Supported MAC Systems

| Distribution | MAC System | Restriction Mechanism |
|-------------|-----------|----------------------|
| Ubuntu 24.04+ | AppArmor | `kernel.apparmor_restrict_unprivileged_userns=1` |
| Fedora 41+ / RHEL 10+ | SELinux | `user_namespace { create }` permission |
| Arch, Void, Gentoo, etc. | None | No restriction — works natively |

### Detection

Canister detects the active MAC system at startup:

1. AppArmor: `/sys/module/apparmor/parameters/enabled` == `"Y"`
2. SELinux: `/sys/fs/selinux/enforce` exists
3. Neither: no policy needed, sandbox works natively

`can check` reports the active MAC system, its restriction status, and the
canister policy status.

### AppArmor (Ubuntu)

**Two-profile architecture:**

Canister uses two AppArmor profiles, managed by `can setup`:

1. **`canister`** — attached to the `can` binary. Grants mount, pivot_root,
   capabilities (`sys_admin`, `net_admin`, `sys_chroot`, `sys_ptrace`,
   `dac_override`, `dac_read_search`), userns creation, and full file/network
   access. Has a catch-all `px /** -> canister//&canister_sandboxed` rule that
   transitions all child exec's to the restricted sub-profile. Also has
   specific `ux` (unconfined exec) rules for:

   - **pasta** (`/usr/bin/pasta`, `/usr/bin/pasta.avx2`, `/bin/pasta`,
     `/bin/pasta.avx2`): pasta needs `CAP_SYS_ADMIN` to call
     `setns(CLONE_NEWUSER)`, which is denied by `canister_sandboxed`. The `ux`
     rules take precedence over the `px /**` glob, so pasta runs unconfined.
   - **apparmor_parser** (`/usr/sbin/apparmor_parser`, `/sbin/apparmor_parser`):
     needs `CAP_MAC_ADMIN` to load/unload profiles during `can setup`.

2. **`canister_sandboxed`** — maximally strict sub-profile for sandboxed
   commands. Denies all capabilities (`audit deny capability`), mount/umount/
   pivot_root, user namespace creation, ptrace (except allowing the
   USER_NOTIF supervisor to read process memory), and DBus.

**Profile transition chain:**

```
canister (binary starts, never execs itself)
    ├─ fork (child inherits "canister") → all namespace setup happens here
    │   └─ execve(command) → "canister//&canister_sandboxed"
    ├─ spawn(pasta) → ux rule fires → runs unconfined
    └─ spawn(apparmor_parser) → ux rule fires → runs unconfined
```

AppArmor specific path rules (`ux /usr/bin/pasta`) take precedence over glob
rules (`px /**`), so the `ux` rules for pasta and apparmor_parser work without
conflicting with the catch-all `px` rule.

**One-time upgrade note:** When upgrading from an older profile (without `ux`
rules for pasta/apparmor_parser) to the new profile, `apparmor_parser` may be
confined by the old profile and fail with "Access denied". In this case,
manually reload: `sudo apparmor_parser -r /etc/apparmor.d/canister`.

### SELinux (Fedora/RHEL)

**Policy module architecture:**

Canister's SELinux policy defines three types:

1. **`canister_t`** — domain for the `can` binary. Grants `user_namespace
   { create }`, `cap_userns { sys_admin sys_ptrace net_admin sys_chroot }`,
   mount/pivot_root permissions, full file access, and ptrace over sandboxed
   children.

2. **`canister_sandboxed_t`** — restricted domain for sandboxed child
   processes. Basic file read/execute and network socket access only. No
   namespace creation, no capabilities, no mount operations.

3. **`canister_exec_t`** — file type for the `can` binary, triggers automatic
   domain transition from `unconfined_t` to `canister_t` on exec.

**Installation:** SELinux policy installation requires `checkmodule`,
`semodule_package`, and `semodule` (from `policycoreutils` and `checkpolicy`
packages). `can setup` generates `.te` (type enforcement) and `.fc` (file
context) files, compiles them, and installs the module.

### Impact on Canister

| Feature | With MAC restriction | With canister policy |
|---------|---------------------|---------------------|
| User namespace | Works | Works |
| Mount namespace | Mounts fail → **aborts** | Full isolation |
| Filesystem isolation | **Aborts** (cannot establish) | Full |
| Network namespace | Works | Works |
| Loopback bring-up | Fails → **aborts** | Works |
| pasta | N/A (no connectivity) | Works |
| Seccomp | Works | Works |
| USER_NOTIF supervisor | Works | Works |

### Policy management (`can setup`)

```bash
# Install the security policy (auto-detects MAC system and binary path)
sudo can setup

# Force reinstall (even if policy exists and appears current)
sudo can setup --force

# Remove the policy
sudo can setup --remove
```

`can setup` is interactive when stdout is a terminal: it shows the generated
policy content (or a diff when updating), and asks for confirmation before
writing. In non-interactive mode (piped/CI), it writes without prompting.

The command auto-detects the active MAC system and generates the appropriate
policy. On systems with no MAC, it reports that no policy is needed.

Stale policy detection: when the installed policy content doesn't match the
current template (e.g., after a Canister upgrade), `can check` reports the
policy as "OUTDATED" and `can setup` will update it.

---

## Known Limitations

### Fundamental limitations

- **Kernel exploits.** No userspace sandbox can protect against kernel
  vulnerabilities. Seccomp reduces the attack surface but cannot eliminate it.

- **Side channels.** Timing attacks, cache attacks, and speculative execution
  attacks are out of scope.

- **RLIMIT_NPROC is per-UID.** The max_pids limit applies to the user's total
  process count, not just the sandbox. Inside a user namespace this is usually
  fine (the sandbox runs as a mapped UID), but if multiple sandboxes share
  a UID they share the limit.

- **DNS resolution timing.** Domain pre-resolution happens at sandbox startup.
  If DNS records change during execution, the resolved IP set becomes stale.
  TTL-aware re-resolution is not implemented.

- **USER_NOTIF TOCTOU window.** The `SECCOMP_IOCTL_NOTIF_ID_VALID` check
  mitigates but does not fully eliminate the time-of-check-time-of-use race
  in the USER_NOTIF supervisor. A highly concurrent, adversarial workload
  with precise timing could theoretically modify memory between the supervisor's
  read and verdict. This is an inherent limitation of the `seccomp_unotify`
  mechanism.
