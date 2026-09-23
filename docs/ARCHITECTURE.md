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
- [Event Stream](#event-stream)
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
├── can-proxy      L7 egress proxy. TLS termination with a dynamic
│                  CA, per-destination contracts, DLP enforcement,
│                  upstream forwarding.
│
├── can-dlp        Detection engine. Credential detectors, encoding
│                  chain recursion, canaries, scope enforcement.
│
├── can-events     Structured event stream (schema v1, ADR-0010).
│                  Envelope, hash chain, socket/file transports.
│                  Opt-in: nothing is emitted without --events-*.
│
└── can-log        Logging setup. TTY detection, human vs JSON
                   output selection, monitor-mode event types
                   and summary output.
```

Dependencies flow downward: `can-cli` -> `can-sandbox` -> `can-policy`,
`can-net`. `can-policy` and `can-log` have no internal dependencies.
`can-events` is used by `can-cli`, `can-sandbox` and `can-proxy`, and
depends on nothing internal.

### Outbound Defense Model (Filtered + Proxy + DLP)

When proxy is enabled with enforcement, outbound networking follows a three-layer model:

1. **Kernel first-line (seccomp USER_NOTIF):** sandboxed processes may only connect to
   local proxy loopback endpoint and DNS server; all other direct outbound INET/INET6
   traffic is denied.
2. **Proxy second-line (user space):** proxy validates destination against allow policy
   and forwards via L7 HTTP interception path or L4 CONNECT passthrough path.
3. **DLP third-line (content scanning):** when `[network.dlp]` is enabled (implicit
   under `--strict` + `proxy`), the L7 path scans request headers, URI, and body
   for credential patterns (GitHub PATs, npm tokens, AWS keys, SSH keys, etc.) and
   enforces per-detector domain scoping. A GitHub PAT bound for `registry.npmjs.org`
   is blocked even though `registry.npmjs.org` has a `[[host]]` block. Bodies are decompressed
   (gzip/deflate/brotli) and decoded (base64/hex/percent, up to 32 layers) before
   pattern matching. See [DLP.md](DLP.md) for the threat model, detector list, and
   canary-token / session-entropy-budget mechanisms.
4. **Fake-secret swap (input substitution):** for env-var secrets named in
   `[network.dlp] fake_secrets`, the sandbox is given a fake value under the real
   variable name while the parent hands the proxy the `fake → real` map. The proxy
   swaps the real value back in only on egress to a host authorised for that
   credential. The real secret never enters the sandbox, so even an encrypted
   exfiltration attempt leaks only the useless fake. See
   [DLP.md § Fake-Secret Swap](DLP.md#fake-secret-swap).

This prevents bypass by unsetting proxy environment variables, and prevents
exfiltration of credentials that the sandbox legitimately needs read access to.

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
│    g. Validate exec, determine network mode                 │
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
Mounted paths are visible inside the sandbox, but `exec` and the
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

The mode is selected via `[unsafe] seccomp_default_allow` in the config file
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

### 4b. Seccomp USER_NOTIF Supervisor (exec path allow-list only)

**Syscall:** `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER)`
**Module:** `notifier/` (`supervisor.rs`, `eval_proc.rs`, `proc_mem.rs`, `fd_channel.rs`)

> **History.** The supervisor used to inspect `connect`/`sendto`/`sendmsg`
> (egress), `clone`/`clone3` (namespaces), and `socket` (types) by reading the
> worker's memory and answering `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. That
> `CONTINUE`-after-read pattern is **TOCTOU-raceable** (issue #4): the kernel
> re-reads the pointed-to argument when it actually executes the syscall, so a
> sibling `CLONE_VM` thread can swap the argument in the check-to-execute
> window. All of those checks were therefore **moved to layers that cannot be
> raced**: register-decidable gates → static BPF (§4); egress → the network
> topology (§3, the worker has no uplink in proxy mode); `clone3` → `ENOSYS`.
> See `docs/notifier-removal-audit.md`.

What remains on USER_NOTIF is **one** check: the per-exec **path** allow-list
(`allow_execve`) for *child* `execve`/`execveat` calls. Classic BPF cannot read
the pathname string (it lives behind a pointer), so the supervisor reads it from
`/proc/<pid>/mem`, canonicalises it, checks it against the allow-list, and
answers `CONTINUE` (allow) or `ERRNO(EACCES)` (deny). `execveat(AT_EMPTY_PATH)`
is denied in static BPF before it ever reaches the supervisor.

**Architecture:** the supervisor runs as **PID 1** in the sandbox's PID
namespace (so it is an ancestor of every worker — Yama `ptrace_scope=1` is
satisfied) with its own procfs mount (so `/proc/<pid>/mem` opens succeed from
the child user namespace). It runs inline, single-threaded, `poll()`ing the
notifier fd with a 200 ms timeout interleaved with non-blocking `waitpid`. The
worker passes the notifier fd to PID 1 over a pipe + `pidfd_getfd()` (not
SCM_RIGHTS). **Requirements:** Linux 5.9+, auto-detected; disabled in monitor
mode; toggled by `[syscalls] notifier`.

#### The residual exec TOCTOU — present, and why it is contained

The exec path check is the one surviving `CONTINUE`-on-inspected-memory path, so
the race still *exists*: a multithreaded worker can show the supervisor an
allowed pathname (e.g. `/usr/bin/python3`) and, from a `CLONE_VM` sibling
thread, rewrite the pointer to a different path (e.g. `/bin/sh`) before the
kernel re-reads it — running a binary the allow-list would have rejected.

This is **contained to a policy bypass with no escalation or escape**, for five
independent reasons. The argument is deliberately defense-in-depth: each point
holds on its own.

1. **The race cannot introduce a binary — only reach one already mounted.** It
   only changes *which path string* the kernel resolves; the path must resolve
   to a real, executable file in the worker's (post-`pivot_root`) mount
   namespace. That filesystem contains only what the recipe author exposed:
   read-only bind mounts of `filesystem.read`. Writable areas (CWD, `/tmp`, the
   root tmpfs, writable binds) are mounted **`noexec` whenever an exec
   allow-list is in force** (see §2 and the invariant below), so the worker
   cannot drop a payload and race-exec it. The reachable set is exactly "the
   binaries the recipe already chose to make available, read-only" — the
   allow-list is a *subset* of that set, and the race can reach the rest of it.

2. **`execve` preserves every confinement layer.** `PR_SET_NO_NEW_PRIVS` is set,
   so setuid/setgid bits and file capabilities are ignored across `execve` — no
   privilege is ever gained by exec. The seccomp filters, the empty capability
   sets, the user/PID/mount/network namespaces, cgroup limits, and rlimits all
   **persist across `execve` unchanged**. So a raced `/bin/sh` runs with
   *identical* privileges and reach to the `python3` it impersonated.

3. **The raced binary still has no escape primitives.** It cannot create or join
   namespaces (`unshare`/`setns` baseline-denied; `clone` ns flags + `clone3`
   denied in static BPF), cannot reach the network directly (no uplink in proxy
   mode), cannot open raw sockets, and cannot remount the rootfs. None of that
   depends on the exec check.

4. **Fileless / memfd exec is independently blocked.** `memfd_create` is
   baseline-denied and `execveat(AT_EMPTY_PATH)` is denied in static BPF, so the
   race cannot be combined with "exec a memfd I just wrote."

5. **The initial command is validated race-free.** `process::validate_execve`
   runs in the trusted parent before launch; the race only affects *child*
   execs.

**The load-bearing invariant:** *the supervisor only enforces a non-trivial exec
allow-list when `process.exec()` is `Allow(paths)`, and in exactly that case
writable mounts are `noexec`.* (`exec = "any"` has no allow-list, so there is
nothing to bypass; `entrypoint-only` seeds no paths either.) So in every
configuration where the race could defeat the allow-list, the worker is *also*
unable to introduce a new executable — the race can only pick a different
recipe-provided, read-only binary, which then runs fully confined.

**Therefore:** the exec allow-list is a **best-effort hardening/policy control**
("limit which of the mounted tools may run"), **not a privilege or escape
boundary.** Treat it as such: if you need a hard guarantee that a particular
binary can never run, do not mount it into the sandbox (or use the optional MAC
backstop — `docs/...`), rather than relying on `allow_execve` alone. The
TOCTOU-affected sandbox-escape class (egress, namespaces) is **closed**; this
residual is a bounded policy-bypass, retained because removing it would either
drop per-recipe child-exec restriction entirely or make it depend on an
enforcing LSM being installed.

### 5. Process Control

**Modules:** `process.rs` (environment filtering, PID namespace, RLIMIT_NPROC,
exec validation)

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

**Fake-secret injection** (`[network.dlp] fake_secrets`): for a marked
secret, the child environment receives a generated *fake* under the real
variable name and any host copy of that variable is stripped first, so
the real value never reaches the sandbox. The real value is captured by
the parent and handed to the egress proxy, which swaps it back in on
authorised egress (see Outbound Defense Model above and
[DLP.md § Fake-Secret Swap](DLP.md#fake-secret-swap)).

**`max_pids`** (`RLIMIT_NPROC`):

Sets `RLIMIT_NPROC` via `setrlimit()` to cap the number of processes the
sandbox can create. This is a per-UID limit — effective because the sandbox
runs as UID 0 in its own user namespace, mapped to the host user.

**Security property:** Prevents fork bombs. A process that exceeds the limit
gets `EAGAIN` from `fork()`.

**`exec`** (pre-exec validation):

The resolved command path is checked against the `exec` list
before forking. If the command is not in the list (and the list is non-empty),
execution is rejected immediately.

**Prefix rules:** Entries ending in `/*` match any binary under that
directory tree. For example, `/nix/store/*` allows any binary whose
resolved path starts with `/nix/store/`. The match requires a `/` boundary
to prevent false positives (e.g., `/nix/store-extra/foo` does NOT match
`/nix/store/*`). This is essential for content-addressed stores like Nix
where binary paths contain unpredictable hashes.

**Limitation:** `exec` validates the *initial* command at the CLI
level. Ongoing enforcement of every `execve()` call inside the sandbox is
provided by the USER_NOTIF supervisor (see
[Seccomp USER_NOTIF Supervisor](#4b-seccomp-user_notif-supervisor)), which
intercepts `execve()` and `execveat()` syscalls and validates the pathname
against the `exec` list. When the notifier is disabled (kernel
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
| `exec` | Rejects unlisted commands | Logs warning, allows through |
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

## Event Stream

Opt-in, off by default. With `--events-socket <path>` (or `--events-file
<path>`) plus `--run-id`, `can` emits one compact JSON object per line
describing what a run did: `run_start`, `policy_resolved`, `process_exec`,
`egress_request`, `contract_violation`, `dlp_block`, `canary_fire`,
`stats` and `run_end` — plus `exchange` when capture is on and
`stream_seal` when signing is.

| Flag | Effect |
|---|---|
| `--events-socket <path>` | Connect to a listening `SOCK_STREAM` Unix socket. |
| `--events-file <path>` | Append JSONL to a file instead. |
| `--run-id <id>` | Stamped on every event (generated when omitted). |
| `--capture-exchanges` | Add an `exchange` event per HTTP exchange (ADR-0011). |
| `--capture-max-bytes <n>` | Per-body capture cap, default 1 MiB. |
| `--stats-interval-ms <ms>` | Cumulative `stats` cadence, default 5000, `0` to disable (ADR-0015). |
| `--canaries-file <path>` | External, tagged canaries for this run (ADR-0012). |
| `--events-sign-key <path>` | Sign each stream's closing seal with this Ed25519 key (ADR-0016). |

`can` is the **client**: the consumer listens on the socket. Every
emitting process opens its own connection, because the CLI, the proxy
process and the USER_NOTIF supervisor are separate processes and
concurrent writes to one stream socket are not atomic. The envelope
therefore carries a `stream` field (`cli`, `proxy`, `supervisor`), and
each stream has its own `seq` counter and hash chain:

```
chain_hash = sha256(line with the trailing `,"chain_hash":"…"` removed)
prev_hash  = the previous event's chain_hash in the same stream
```

A consumer detects dropped, reordered or rewritten lines without
re-serializing anything. The full schema is published as
`docs/events-schema-v1.json` and generated from `can-events`; the design
rationale is ADR-0010.

The sandboxed workload can never write to the stream: connections are
opened `CLOEXEC` before any namespace work, and the worker branch drops
its inherited handle before the workload runs.

### Seals

The chain proves a stream is internally *consistent*; it does not say
who wrote it, because anyone holding the file can rewrite a line and
recompute every hash after it. With `--events-sign-key`, each emitting
process closes its stream with a `stream_seal` event: an Ed25519
signature over

```
canister-event-stream-v1\n<run_id>\n<stream>\n<events>\n<chain_head>
```

One signature commits to the whole stream, since the chain binds each
event to its predecessor. The key is read before any namespace is
entered and never reaches the workload. A stream with no seal is
*unsealed*, not invalid — a killed process never gets to sign, and
crashing is not forgery. See ADR-0016.

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
